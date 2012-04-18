#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import errno
import fuse
import os
import stat
import threading
import time

from argparse import ArgumentParser
from binascii import b2a_hex
from collections import namedtuple
from fuse import FUSE, FuseOSError, LoggingMixIn, Operations
from io import BufferedReader, BytesIO, FileIO, RawIOBase
from os import path
from struct import Struct

ZIP_STREAM_ITEM = Struct('<4s5H3L2H')
DESCRIPTOR = Struct('<3L')
STREAM_ITEM = Struct('<4s5H3L2HB20s')
JUMP_ITEM = Struct('<2Q')
HEADER_DIFF = ZIP_STREAM_ITEM.size - STREAM_ITEM.size

Descriptor = namedtuple('Descriptor', 'crc compressed_size raw_size')
StreamItem = namedtuple('StreamItem',
        ('signature', 'needed_version', 'flag', 'compression',
         'mod_time', 'mod_date', 'crc', 'compressed_size', 'raw_size',
         'filename_len', 'extra_field_len', 'descriptor_len', 'sha'))

class SeekTree(object):
    __slots__ = ('location', 'left', 'right')

    def __init__(self, location, left=None, right=None):
        self.location = location
        self.left = left
        self.right = right

    @staticmethod
    def load(iterator):
        last_level = ((SeekTree(i), i[0]) for i in iterator)
        top_level = []
        loop = True

        while loop:
            while True:
                try:
                    left_tree, left_min = next(last_level)
                except StopIteration:
                    break

                try:
                    right_tree, right_min = next(last_level)
                except StopIteration:
                    top_level.append((left_tree, left_min))
                else:
                    top_level.append((SeekTree(right_min, left=left_tree,
                                               right=right_tree),
                                      left_min))

            loop = len(top_level) > 1
            last_level, top_level = iter(top_level), []

        try:
            return next(last_level)[0]
        except StopIteration:
            return

    def find(self, offset):
        if isinstance(self.location, tuple):
            return self
        elif offset < self.location:
            return self.left.find(offset)
        else:
            return self.right.find(offset)


def _unpack_stream(stream, struct):
    return (struct.unpack(item)
            for item in iter(lambda: stream.read(struct.size), b''))

ExplodedInfo = namedtuple('ExplodedInfo',
                          'filesize directory_offset jump_tree')

class ExplodedZip(Operations):
    def __init__(self, base='.', depth=0):
        self.base = path.realpath(base)
        self.depth = depth
        self._load_time = time.time()
        self.__exploded_info = {}
        self.__handles = {}
        self.__fh = 0
        self.__fh_lock = threading.Lock()

    def _exploded_info(self, path):
        if path in self.__exploded_info: return self.__exploded_info[path]

        jump_name = os.path.join(self.base, 'meta',
                                 os.path.basename(path) + '.jump')

        with open(jump_name, 'rb') as jump:
            filesize, dir_offset = JUMP_ITEM.unpack(jump.read(JUMP_ITEM.size))
            tree = SeekTree.load(_unpack_stream(jump, JUMP_ITEM))

            info = self.__exploded_info[path] = ExplodedInfo(filesize,
                                                             dir_offset, tree)

            return info

    def _metafiles(self, path):
        meta = os.path.join(self.base, 'meta', os.path.basename(path))
        return [meta + suffix for suffix in ('.dir', '.stream', '.jump')]

    @staticmethod
    def _not_supported(*args, **kargs):
        raise FuseOSError(fuse.ENOTSUP)

    def access(self, path, amode):
        # this is a read only file system
        if amode & os.W_OK: return -errno.EACCES
        if path == '/': return 0

        # as long as the user is able to access all of the meta files it's ok
        if all(os.access(f, amode) for f in self._metafiles(path)):
            return 0
        else:
            return -errno.EACCES

    def chmod(self, path, mode):
        if path == '/': return -errno.EACCES

        file_info = [(f, os.stat(f).st_mode) for f in self._metafiles(path)]

        try:
            for filename, current_mode in file_info:
                if current_mode != mode:
                    os.chmod(filename, mode)
        except:
            try:
                for filename, previous_mode in file_info:
                    if os.stat(filename).st_mode != previous_mode:
                        os.chmod(filename, previous_mode)
            except:
                # there's not really anything we can do at this point
                pass

            return -errno.EACCES
        return 0

    def chown(self, path, gid, uid):
        if path == '/': return -errno.EACCES

        file_info = [(f, os.stat(f)) for f in self._metafiles(path)]

        try:
            for filename, stat in file_info:
                if gid != stat.st_gid or uid != stat.st_uid:
                    os.chown(filename, gid, uid)
        except:
            try:
                for filename, previous in file_info:
                    current = os.stat(filename)

                    if (current.st_gid != previous.st_gid or
                        current_mode.st_uid != previous.st_uid):

                        os.chown(filename, previous.st_gid, previous.st_uid)

            except:
                # there's not really anything we can do at this point
                pass

            return -errno.EACCES
        return 0

    create = _not_supported

    def destroy(self, path):
        self.__exploded_info = {}
        self.__handles = {}

    def getattr(self, path, fh=None):
        if path == '/':
            uid, gid, pid = fuse.fuse_get_context()

            return {
                'st_uid': uid,
                'st_gid': gid,
                'st_mode': stat.S_IFDIR | 0555,
                'st_nlink': 2,

                'st_atime': self._load_time,
                'st_mtime': self._load_time,
                'st_ctime': self._load_time,
            }
        else:
            stats = [os.stat(f) for f in self._metafiles(path)]

            # bitwise OR of all the modes
            mode = reduce(lambda a, b: a | (b.st_mode & 0777), stats, 0)

            return {
                'st_uid': stats[0].st_uid,
                'st_gid': stats[0].st_gid,
                'st_mode': stat.S_IFREG |  mode,
                'st_size': self._exploded_info(path).filesize,
                'st_nlink': min(i.st_nlink for i in stats),

                'st_atime': max(i.st_atime for i in stats),
                'st_mtime': max(i.st_mtime for i in stats),
                'st_ctime': max(i.st_ctime for i in stats),
            }


    def link(self, target, source):
        for t, s in zip(self._metafiles(target), self._metafiles(source)):
            if not path.isfile(t) or not path.samefile(s, t):
                os.link(s, t)

    listxattr = _not_supported
    mkdir = _not_supported
    mknod = _not_supported

    def open(self, path, flags):
        with self.__fh_lock:
            raw = File(path, flags, self._exploded_info(path), fh=self.__fh,
                       base=self.base, depth=self.depth)

            self.__handles[self.__fh] = threading.Lock(), BufferedReader(raw)

            self.__fh += 1
            return raw.fh

    def read(self, path, size, offset, fh):
        lock, reader = self.__handles[fh]

        with lock:
            reader.seek(offset)
            return reader.read(size)

    def readdir(self, path, fh):
        if path != '/':
            raise FuseOSError(errno.ENOTDIR)

        yield '.'
        yield '..'
        for entry in os.listdir(os.path.join(self.base, 'meta')):
            if entry.endswith('.dir'):
                yield os.path.basename(entry[:-4])

    def readlink(self, path):
        for meta in self._metafiles(path):
            link = os.readlink(meta)

            try:
                name, ext = link.rsplit('.', 1)

                if meta.rsplit('.', 1)[1] == ext:
                    return name
            except ValueError:
                continue

        return -errno.EINVAL

    def release(self, path, fh):
        del self.__handles[fh]

    removexattr = _not_supported
    rename = _not_supported
    rmdir = _not_supported

    def statfs(self, path):
        # TODO: report better information
        stat = os.statvfs(os.path.join(self.base, 'meta'))
        return dict((key, getattr(stat, key)) for key in
                    ('f_bavail', 'f_bfree', 'f_blocks', 'f_bsize'))

    def symlink(self, target, source):
        for t, s in zip(self._metafiles(target), self._metafiles(source)):
            if not path.islink(t) or os.readlink(t) != s:
                os.symlink(s, t)

    truncate = _not_supported
    unlink = _not_supported

    def utimens(self, path, time=None):
        for filename in self._metafiles(path):
            os.utime(filename, time)

    write = _not_supported



def _read_stream(stream, offset=0, count=-1, base='.', depth=0):
    if offset < 0:
        raise ValueError('offset %r should be greater than zero' % offset)

    out = BytesIO()
    header_diff = ZIP_STREAM_ITEM.size - STREAM_ITEM.size

    while count < 0 or out.tell() < count:
        raw_header = stream.read(STREAM_ITEM.size)
        if not raw_header: break

        header = STREAM_ITEM.unpack(raw_header)
        var_fields = header[9] + header[10]
        descriptor_len = header[11]
        sha1 = b2a_hex(header[12])

        data_name = path.join(*([base, 'data'] + list(sha1[:depth]) + [sha1]))

        if offset:
            if offset < ZIP_STREAM_ITEM.size:
                out.write(raw_header[offset:header_diff])
                offset = 0
            else:
                offset -= ZIP_STREAM_ITEM.size

            if offset < var_fields:
                stream.seek(offset, 1)
                out.write(stream.read(var_fields - offset))
                offset = 0
            else:
                offset -= var_fields
                stream.seek(var_fields, 1)

            if 0 < count < out.tell():
                out.seek(0)
                return out.read(count)

            with open(data_name, 'rb') as data:
                if count > 0:
                    out.write(data.read(count - out.tell()))
                else:
                    out.write(data.read())

            out.write(stream.read(descriptor_len))

            if 0 < count < out.tell():
                out.seek(0)
                return out.read(count)

        else:
            out.write(raw_header[:header_diff])
            out.write(stream.read(var_fields))

            if 0 < count < out.tell():
                out.seek(0)
                return out.read(count)

            with open(data_name, 'rb') as data:
                if count > 0:
                    out.write(data.read(count - out.tell()))
                else:
                    out.write(data.read())

            out.write(stream.read(descriptor_len))

            if 0 < count < out.tell():
                out.seek(0)
                return out.read(count)

    # count == 0 or count > stream
    out.seek(0)
    return out.read()

def read(filename, offset=0, count=-1, begining=True, base='.', depth=0):
    meta = path.join(base, 'meta', filename)

    with open(meta + '.jump', 'rb') as jump:
        with open(meta + '.dir', 'rb') as dir:
            with open(meta + '.stream', 'rb') as stream:
                header = JUMP_ITEM.unpack(jump.read(JUMP_ITEM.size))
                filesize, directory_offset = header

                tree = SeekTree.load(_unpack_stream(jump, JUMP_ITEM))

                if not begining:
                    offset += filesize

                # open and seek to the location in the ``meta/*.dir`` file
                if offset >= directory_offset:
                    dir.seek(offset - directory_offset)
                    if count > 0:
                        return dir.read(count)
                    else:
                        return dir.read()

                # use the seek tree to find where to seek to
                if offset > 0:
                    pos = tree.find(offset).location
                    offset -= pos[0]
                    stream.seek(pos[1])

                s = _read_stream(stream, offset=offset, count=count,
                                 base=base, depth=depth)

                if count > 0:
                    if len(s) >= count:
                        return s[:count]
                    else:
                        return s + dir.read(count - len(s))

                return s + dir.read()


class File(RawIOBase):
    HEADER = 0
    DATA = 1
    DESCRIPTOR = 2
    DIRECTORY = 3

    def __init__(self, path, flags, info, fh=None, base='.', depth=0):
        super(File, self).__init__()

        self.path = path
        self.flags = flags
        self.fh = fh

        self.info = info
        self.depth = depth
        self.cursor = 0
        self.offset = 0
        self.state = File.HEADER

        # stream item info
        self.stream_offset = 0
        self.zip_header = b''
        self.descriptor = b''

        # data file info
        self.data = None
        self.data_name = ''
        self.data_len = 0

        # streams
        prefix = os.path.join(base, 'meta', os.path.basename(path))
        self.stream = FileIO(prefix + '.stream', 'rb')
        self.dir = FileIO(prefix + '.dir', 'rb')
        self.data_dir = os.path.join(base, 'data')

        # init
        self._load_stream_item()
        self.lock = threading.Lock()

    def _load_stream_item(self):
        if self.data:
            self.data.close()
            self.data = None

        # open the header so we can know the data file to open, and the
        # length of the var fields
        raw_header = self.stream.read(STREAM_ITEM.size)
        header = StreamItem._make(STREAM_ITEM.unpack(raw_header))

        var_fields = header.filename_len + header.extra_field_len
        sha1 = b2a_hex(header.sha)

        # only save the zip part of the header
        self.zip_header = (raw_header[:HEADER_DIFF] +
                           self.stream.read(var_fields))

        self.descriptor = self.stream.read(header.descriptor_len)

        self.data_name = path.join(*([self.data_dir] +
                                     list(sha1[:self.depth]) + [sha1]))

    def _open_data_file(self):
        self.data = FileIO(self.data_name, 'rb')
        self.data_len = self.data.seek(0, 2)
        self.data.seek(0)

    def close(self):
        self.stream.close()
        self.dir.close()
        if self.data: self.data.close()

    def fileno(self):
        return self.fh

    def isatty(self):
        return False

    def read(self, count=-1):
        if count < 0: return self.readall()
        elif count == 0: return b''

        state = self.state
        if state == File.HEADER:
            previous_offset = self.offset
            self.offset += count

            result = self.zip_header[previous_offset:self.offset]
            self.cursor += len(result)

            if self.offset >= len(self.zip_header):
                self.state = File.DATA
                if not self.data: self._open_data_file()

            return result

        elif state == File.DATA:
            result = self.data.read(count)
            self.cursor += len(result)

            if self.data.tell() >= self.data_len:
                self.state = File.DESCRIPTOR
                self.offset = 0

            # empty data file (state will now be DESCRIPTOR)
            if not result: return self.read(count)

            return result

        elif state == File.DESCRIPTOR:
            previous_offset = self.offset
            self.offset += count

            result = self.descriptor[previous_offset:self.offset]
            self.cursor += len(result)

            if self.offset >= len(self.descriptor):
                if self.cursor >= self.info.directory_offset:
                    self.state = File.DIRECTORY
                    self.dir.seek(0)
                    self.stream_offset = None

                    if self.data:
                        self.data.close()
                        self.data = None

                else:
                    self.state = File.HEADER
                    self.offset = 0
                    self.stream_offset = self.stream.tell()
                    self._load_stream_item()

            # descriptor is optional (state will now be HEADER or DIRECTORY)
            if not result: return self.read(count)

            return result
        elif state == File.DIRECTORY:
            result = self.dir.read(count)
            self.cursor += len(result)

            return result
        else:
            raise RuntimeError('Invalid state: %r' % self.state)

    def readable(self):
        return True

    def readinto(self, b):
        count = len(b)
        if count == 0: return 0

        state = self.state
        if state == File.HEADER:
            header_len = len(self.zip_header)
            previous_offset = self.offset

            current_offset = self.offset = \
                    min(previous_offset + count, header_len)

            read = current_offset - previous_offset
            b[:read] = self.zip_header[previous_offset:current_offset]
            self.cursor += read

            if current_offset == header_len:
                self.state = File.DATA
                if not self.data: self._open_data_file()

            return read

        elif state == File.DATA:
            read = self.data.readinto(b)
            self.cursor += read

            if self.data.tell() >= self.data_len:
                self.state = File.DESCRIPTOR
                self.offset = 0

            # empty data file (state will now be DESCRIPTOR)
            if not read: return self.readinto(b)

            return read

        elif state == File.DESCRIPTOR:
            descriptor_len = len(self.descriptor)
            previous_offset = self.offset

            current_offset = self.offset = \
                    min(previous_offset + count, descriptor_len)

            read = current_offset - previous_offset
            b[:read] = self.descriptor[previous_offset:current_offset]
            self.cursor += read

            if current_offset == descriptor_len:
                if self.cursor >= self.info.directory_offset:
                    self.state = File.DIRECTORY
                    self.dir.seek(0)
                    self.stream_offset = None

                    if self.data:
                        self.data.close()
                        self.data = None

                else:
                    self.state = File.HEADER
                    self.offset = 0
                    self.stream_offset = self.stream.tell()
                    self._load_stream_item()

            # descriptor is optional (state will now be HEADER or DIRECTORY)
            if not read: return self.readinto(b)

            return read
        elif state == File.DIRECTORY:
            read = self.dir.readinto(b)
            self.cursor += read

            return read
        else:
            raise RuntimeError('Invalid state: %r' % self.state)

    def seek(self, pos, offset=0):
        if offset == 1:
            pos += self.cursor
        elif offset == 2:
            pos += self.info.filesize

        if pos == self.cursor: return pos
        self.cursor = pos

        # skip directly to the central directory
        if pos >= self.info.directory_offset:
            if self.data:
                self.data.close()
                self.data = None

            self.state = File.DIRECTORY
            self.stream_offset = None
            self.dir.seek(pos - self.info.directory_offset)
            return pos

        # calculate the offset into the stream file
        z_offset, s_offset = self.info.jump_tree.find(pos).location
        additional = pos - z_offset

        # we're looking at a different data file
        # (load local header into memory)
        if s_offset != self.stream_offset:
            self.stream_offset = s_offset
            self.stream.seek(s_offset)
            self._load_stream_item()

        header_len = len(self.zip_header)
        if additional < header_len:
            self.state = File.HEADER
            self.offset = additional
            return pos

        # assume currently in the data file
        additional -= header_len
        self.state = File.DATA

        # if the file hasn't been opened yet, open it and find its size
        if not self.data: self._open_data_file()

        if additional < self.data_len:
            self.data.seek(additional)
        else:
            self.state = File.DESCRIPTOR
            self.offset = additional - self.data_len

        return pos

    def seekable(self):
        return True

    def tell(self):
        return self.cursor

    def writeable(self):
        return False




parser = ArgumentParser(description='Exposes exploded zip file(s) as a FUSE '
                                    'file system.')

parser.add_argument('-d', '--directory', metavar='DIR', default='.',
                    help='alternate base for the exploded files')

parser.add_argument('--depth', type=int, default=0,
                    help='data subdirectory depth')

parser.add_argument('-D', '--debug', action='store_true', default=False,
                    help='enable FUSE debugging mode')

parser.add_argument('-b', '--background', action='store_true', default=False,
                    help='do not exit until the file system is unmounted')

parser.add_argument('-s', '--single-threaded', action='store_true',
                    default=False, help='do not run in multi-threaded mode')

parser.add_argument('mount', help='mount point')

if __name__ == '__main__':
    args = parser.parse_args()

    fuse = FUSE(ExplodedZip(base=args.directory, depth=args.depth),
                args.mount, foreground=not args.background, ro=True,
                debug=args.debug, nothreads=args.single_threaded)
