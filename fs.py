#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

from binascii import b2a_hex
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


def _read_jump_file(file):
    while True:
        item = file.read(JUMP_ITEM.size)
        if not item: break

        yield JUMP_ITEM.unpack(item)

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
    data = path.join('data', filename)

    with open(meta + '.jump', 'rb') as jump:
        with open(meta + '.dir', 'rb') as dir:
            with open(meta + '.stream', 'rb') as stream:
                header = JUMP_ITEM.unpack(jump.read(JUMP_ITEM.size))
                filesize, directory_offset = header

                tree = SeekTree.load(_read_jump_file(jump))

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

    sys.stdout.write(read(sys.argv[1]))
