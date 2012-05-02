#!/usr/bin/env python
# vim: set fileencoding=utf-8 :

from setuptools import setup, find_packages

try:
    from lib2to3 import refactor
    fixers = set(refactor.get_fixers_from_package('lib2to3.fixes'))
except ImportError:
    fixers = set()

with open('README') as readme:
    documentation = readme.read()

setup(
        name = 'xzip',
        version = '0.10',
        packages = find_packages(),

        install_requires = ['fusepy>=1.1'],

        author = 'Terence Honles',
        author_email = 'terence@honles.com',
        description = 'E[x]ploded zip file system in FUSE',
        long_description = documentation,
        license = 'PSF',
        keywords = 'FS FileSystem File System Zip Deduplication',
        url = 'https://github.com/terencehonles/xzip',

        entry_points = {
            'console_scripts': [
                'zipexplode = xzip.explode:main',
                'zipanaylze = xzip.anaylze:main',
                'mount.xzip = xzip.fs:main',
            ],
        },


        use_2to3 = True,
        # only use the following fixers (everything else is already compatible)
        use_2to3_exclude_fixers = fixers - set([
            'lib2to3.fixes.fix_except',
            'lib2to3.fixes.fix_future',
            'lib2to3.fixes.fix_numliterals',
            'lib2to3.fixes.fix_reduce',
        ]),

        classifiers = [
            'Development Status :: 4 - Beta',
            'Environment :: Console',
            'Intended Audience :: Information Technology',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: Python Software Foundation License',
            'Operating System :: MacOS',
            'Operating System :: POSIX',
            'Operating System :: Unix',
            'Programming Language :: Python :: 2',
            'Programming Language :: Python :: 3',
            'Topic :: System :: Filesystems',
        ]
)
