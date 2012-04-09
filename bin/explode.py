#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import os
import struct
import sys
import zlib

from collections import namedtuple
from hashlib import sha1
from os import path


class _Struct(struct.Struct):
    __slots__ = ('marker', '_named_ctor')

    def __init__(self, format, marker):
        super(_Struct, self).__init__(format)
        self.marker = marker

    def unpack(self, data):
        raw = super(_Struct, self).unpack(data)

        try:
            return self._named_ctor(raw)
        except AttributeError:
            return raw

CENTRAL_DIR = _Struct('<4s6H3L5H2L', b'PK\x01\x02')
CENTRAL_DIR._named_ctor = namedtuple('CentralDirectory',
        ('signature', 'creator_version', 'needed_version', 'flag',
         'compression', 'mod_time', 'mod_date', 'crc', 'compressed_size',
         'raw_size', 'filename_len', 'extra_field_len', 'comment_len',
         'disk_num_start', 'internal_attr', 'external_attr', 'offset'))._make

END_OF_DIR = _Struct('<4s4H2LH', b'PK\x05\x06')
END_OF_DIR._named_ctor = namedtuple('EndOfArchive',
        ('signature', 'disk_num', 'first_disk', 'local_entries',
         'total_entries', 'directory_size', 'directory_offset',
         'comment_len'))._make

LOCAL_HEADER = _Struct('<4s5H3L2H', b'PK\x03\x04')
LOCAL_HEADER._named_ctor = namedtuple('LocalHeader',
        ('signature', 'needed_version', 'flag', 'compression',
         'mod_time', 'mod_date', 'crc', 'compressed_size', 'raw_size',
         'filename_len', 'extra_field_len'))._make

DATA_DESCRIPTOR = _Struct('<3L', b'PK\x07\x08')
DATA_DESCRIPTOR._named_ctor = namedtuple('DataDescriptor',
        ('crc', 'compressed_size', 'raw_size'))._make

STREAM_ITEM = struct.Struct('<4s5H3L2HB20s')
JUMP_ITEM = struct.Struct('<2Q')


def process_zip(filename):
    with open(filename, 'rb') as file:
        try:
            file.seek(-END_OF_DIR.size, 2)
        except IOError:
            # file too small, probably not a zip
            return

        eoa = END_OF_DIR.unpack(file.read())
        filesize = file.tell()
        if eoa.signature != END_OF_DIR.marker:
            file.seek(max(file.tell() - (2 ** 16 + END_OF_DIR.size), 0))
            tmp = file.read()
            index = tmp.rfind(END_OF_DIR.marker)
            if index < 0: return

            eoa = END_OF_DIR.unpack(tmp[index:index + END_OF_DIR.size])

        for dir in ('meta', 'data'):
            if not path.isdir(dir): os.makedirs(dir)

        prefix = path.join('meta', path.basename(filename))
        with open(prefix + '.jump', 'wb') as jump:
            with open(prefix + '.stream', 'wb') as stream:
                with open(prefix + '.dir', 'wb') as dir:

                    jump.write(JUMP_ITEM.pack(filesize, eoa.directory_offset))
                    file.seek(eoa.directory_offset)
                    for _ in range(eoa.total_entries):
                        info = file.read(CENTRAL_DIR.size)
                        dir.write(info)

                        info = CENTRAL_DIR.unpack(info)

                        # write to the jump file a mapping from zip to
                        # stream location
                        jump.write(JUMP_ITEM.pack(info.offset, stream.tell()))

                        process_file(file, info, stream)

                        dir.write(file.read(info.filename_len +
                                  info.extra_field_len + info.comment_len))

                    # copy the rest of the file following the central
                    # directory items
                    dir.write(file.read())


def process_file(file, info, stream):
    pos = file.tell()

    # go to the local header and unpack it
    file.seek(info.offset)
    header = LOCAL_HEADER.unpack(file.read(LOCAL_HEADER.size))

    # save the filename and extra fields
    var_fields = file.read(header.filename_len + header.extra_field_len)

    # header doesn't always have the size, so it's safer to use the central
    # directory information
    data = file.read(info.compressed_size)

    sha = sha1(data)

    data_name = path.join('data', sha.hexdigest())
    if not path.isfile(data_name):
        with open(data_name, 'wb') as d:
            d.write(data)

    descriptor = b''

    # check if there is a data descriptor here
    if file.read(len(DATA_DESCRIPTOR.marker)) == DATA_DESCRIPTOR.marker:
        descriptor = DATA_DESCRIPTOR.marker + file.read(DATA_DESCRIPTOR.size)

    elif header.flag & 0b1000:
        file.seek(-len(DATA_DESCRIPTOR.marker), 1)
        descriptor = file.read(DATA_DESCRIPTOR.size)

    # the length of the descriptor allows us to not have to do the above logic
    # and the hex digest allows us to request the shared data to fill the
    # stream
    stream.write(STREAM_ITEM.pack(*(header + (len(descriptor), sha.digest()))))
    stream.write(var_fields)
    if descriptor: stream.write(descriptor)

    file.seek(pos)


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        process_zip(arg)
