#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

from setuptools import setup, find_packages

setup(
        name = 'xzip',
        version = '0.9',
        packages = find_packages(),

        install_requires = ['fusepy>=1.1'],

        author = 'Terence Honles',
        author_email = 'terence@honles.com',
        description = 'E[x]ploded zip file system in FUSE',
        license = 'PSF',
        keywords = 'FS FileSystem File System Zip Deduplication',

        entry_points = {
            'console_scripts': [
                'zipexplode = xzip.explode:main',
                'zipanaylze = xzip.anaylze:main',
                'mount.xzip = xzip.fs:main',
            ],
        },

        classifiers = [
            'Development Status :: 4 - Beta',
            'Environment :: Console',
            'Intended Audience :: Information Technology',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: Python Software Foundation License',
            'Operating System :: MacOS',
            'Operating System :: POSIX',
            'Operating System :: Unix',
            'Topic :: System :: Filesystems',
        ]
)
