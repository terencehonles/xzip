E[x]ploded Zip File System
==========================

``xzip`` is a FUSE_ file system for deduplicating zip files which share zipped
contents.

To install use::

    $ pip install xzip

    or

    $ easy_install xzip

``xzip`` provides three executables ``zipexplode``, ``zipanalyze``, and
``mount.xzip`` which will "explode" a zip, analyze a zip file, and mount
exploded zips respectively.

The file structure for an exploded zip is the following::

    $ zipexplode path/to/zip/name-of-zip.zip
    $ tree .
    .
    ├── data
    │   ├── <sha1-data-file1>
    │   ├── <sha1-data-file2>
    │   ├── ...
    │   └── <sha1-data-filen>
    └── meta
        ├── name-of-zip.zip.dir
        ├── name-of-zip.zip.jump
        └── name-of-zip.zip.stream

The file structure would be mounted by::

    $ mount.xzip . path/to/mount/point
    $ ls path/to/mount/point
    name-of-zip.zip


Data files may be shared between any number of exploded zips files, and the
meta tuple (``*.dir``, ``*.jump``, ``*.stream``) describe the original zip
file.


``zipexplode`` accepts two options ``--directory`` and ``--depth`` to modify
where it creates the ``data`` and ``meta`` directories and how many levels deep
the ``data`` directory should be. ``zipexplode`` can explode multiple zip files
at once, and additional help is provided with the ``--help`` option.


``zipanalyze`` simply prints out the sha1 of different segments of the original
zip file. This script was used to determine what could be deduplicated, and
what needed to be stored per zip file. This executable is mainly of historical
use.

``mount.xzip`` will mount the directory structure described above, and needs to
be supplied with matching ``directory`` and ``--depth`` arguments to when
``zipexplode`` was called.  Additional arguments ``--debug``, ``--foreground``,
and ``--single-threaded`` are passed to FUSE_ and control underlying
functionality. For more information see the ``--help`` for ``mount.xzip``.
(``mount.xzip`` also takes ``-o`` style options)

**Note: At this time  xzip is not zip64 safe**

.. _FUSE: http://fuse.sourceforge.net/
