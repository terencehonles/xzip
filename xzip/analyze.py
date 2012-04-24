#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

import csv
import struct
import sys
import zlib

from collections import namedtuple
from hashlib import sha1

__all__ = ('CENTRAL_DIR', 'END_OF_DIR', 'LOCAL_HEADER', 'DATA_DESCRIPTOR',
           'process_zip')

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

WRITER = csv.writer(sys.stdout)

def process_zip(filename):
    with open(filename, 'rb') as file:
        try:
            file.seek(-END_OF_DIR.size, 2)
        except IOError:
            # file too small, probably not a zip
            return

        eoa = END_OF_DIR.unpack(file.read())
        if eoa.signature != END_OF_DIR.marker:
            file.seek(max(file.tell() - (2 ** 16 + END_OF_DIR.size), 0))
            tmp = file.read()
            index = tmp.rfind(END_OF_DIR.marker)
            if index < 0: return

            eoa = END_OF_DIR.unpack(tmp[index:index + END_OF_DIR.size])


        WRITER.writerow(('Filename', 'Stream Hash', 'Raw Hash',
                         'Decompressed Hash'))

        file.seek(eoa.directory_offset)
        for _ in range(eoa.total_entries):
            info = CENTRAL_DIR.unpack(file.read(CENTRAL_DIR.size))
            WRITER.writerow(process_file(file, info))
            file.read(info.filename_len + info.extra_field_len +
                      info.comment_len)


def process_file(file, info):
    pos = file.tell()
    hash = sha1()

    # go to the local header and unpack it
    file.seek(info.offset)
    header = file.read(LOCAL_HEADER.size)
    hash.update(header)
    header = LOCAL_HEADER.unpack(header)

    # save the filename (assume utf-8 even though cp437 was what PKWARE
    # used initially)
    filename = file.read(header.filename_len).decode('utf-8')
    hash.update(filename)

    # read the extra field and the compressed data (header doesn't always have
    # the size, so it's safer to use the central directory information)
    hash.update(file.read(header.extra_field_len))
    data = file.read(info.compressed_size)
    hash.update(data)

    if header.compression == 8:
        decompressed = zlib.decompress(data, -15)
    else:
        decompressed = data

    # check if there is a data descriptor here
    if file.read(len(DATA_DESCRIPTOR.marker)) == DATA_DESCRIPTOR.marker:
        hash.update(DATA_DESCRIPTOR.marker)
        hash.update(file.read(DATA_DESCRIPTOR.size))

    elif header.flag & 3:
        file.seek(-len(DATA_DESCRIPTOR.marker), 1)
        hash.update(file.read(DATA_DESCRIPTOR.size))

    file.seek(pos)
    return (filename, hash.hexdigest(), sha1(data).hexdigest(),
            sha1(decompressed).hexdigest())


def main():
    process_zip(sys.argv[1])

if __name__ == '__main__':
    main()
