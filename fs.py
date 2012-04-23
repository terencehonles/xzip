#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import errno
import fuse
import os
import stat
import time

from binascii import b2a_hex
from collections import namedtuple
from fuse import FUSE, FuseOSError, LoggingMixIn, Operations
from glob import iglob
from io import BytesIO
from os import path
from struct import Struct

ZIP_STREAM_ITEM = Struct('<4s5H3L2H')
STREAM_ITEM = Struct('<4s5H3L2HB20s')
JUMP_ITEM = Struct('<2Q')

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
    def __init__(self):
        self._load_time = time.time()
        self.__exploded_info = {}

    def _exploded_info(self, path):
        if path in self.__exploded_info: return self.__exploded_info[path]

        jump_name = os.path.join('meta', os.path.basename(path) + '.jump')
        with open(jump_name, 'rb') as jump:
            filesize, dir_offset = JUMP_ITEM.unpack(jump.read(JUMP_ITEM.size))
            tree = SeekTree.load(_unpack_stream(jump, JUMP_ITEM))

            info = self.__exploded_info[path] = ExplodedInfo(filesize,
                                                             dir_offset, tree)

            return info

    @staticmethod
    def _metafiles(path):
        meta = os.path.join('meta', os.path.basename(path))
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

    # TODO: open
    # TODO: read
    def readdir(self, path, fh):
        if path != '/':
            raise FuseOSError(errno.ENOTDIR)

        yield '.'
        yield '..'
        for entry in iglob('meta/*.dir'):
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

    # TODO: release (close?)

    removexattr = _not_supported
    rename = _not_supported
    rmdir = _not_supported

    def statfs(self, path):
        # TODO: report better information
        stat = os.statvfs('meta')
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



def _read_stream(stream, offset=0, count=-1):
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

            with open(path.join('data', sha1), 'rb') as data:
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

            with open(path.join('data', sha1), 'rb') as data:
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

def read(filename, offset=0, count=-1, begining=True):
    meta = path.join('meta', filename)

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

                s = _read_stream(stream, offset, count)

                if count > 0:
                    if len(s) >= count:
                        return s[:count]
                    else:
                        return s + dir.read(count - len(s))

                return s + dir.read()


if __name__ == '__main__':
    import sys

    fuse = FUSE(ExplodedZip(), sys.argv[1], foreground=True, ro=True)
