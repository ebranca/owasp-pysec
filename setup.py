#!/usr/bin/env python
# Python Security Project (PySec) and its related class files.
#
# PySec is a set of tools for secure application development under Linux
#
# Copyright 2014 PySec development team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# -*- coding: ascii -*-
from distutils.core import setup, Extension

packages = [
    'pysec',
    'pysec.buffer',
    'pysec.core',
    'pysec.heap',
    'pysec.io',
    'pysec.kv',
    'pysec.lang',
    'pysec.net',
]

classifiers = [
    'Development Status :: 0 - Alpha',
    'Intended Audience :: Developers',
    'Programming Language :: Python :: 2.7',
    'License :: Apache 2.0',
    'Operating System :: Linux',
]

exts = [
    Extension('pysec.core.unistd', ['pysec/core/unistd.c'], libraries=['crypt']),
    Extension('pysec.core.fcntl', ['pysec/core/fcntl.c']),
    Extension('pysec.core.stat', ['pysec/core/stat.c']),
    Extension('pysec.core.memory', ['pysec/core/memory.c']),
    Extension('pysec.core.dirent', ['pysec/core/dirent.c']),
    Extension('pysec.core.socket', ['pysec/core/socket.c']),
    Extension('pysec.heap.fibonacci', ['pysec/heap/fibonacci.c']),
    Extension('pysec.buffer.ring', ['pysec/buffer/ring.c'])
]

setup(name='pysec',
      version='0.0',
      description='PySec is a set of tools for secure application development under Linux',
      author='Python security project\'s team',
      author_email='enrico.branca@owasp.org',
      url='http://www.pythonsecurity.org/',
      packages=packages,
      ext_modules=exts,
      classifiers=classifiers,
     )

version = '0.0.1a0'

setup(name='pysec',
      version=version,
      description="PySec is a set of tools for secure application development under Linux",
      long_description=open("README.md", 'rb').read(),
      classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: C',
        'Topic :: Security',
      ],
      keywords='owasp security',
      author='OWASP Python Security Project\' team',
      author_email='enrico.branca@owasp.org',
      url='http://pythonsecurity.org',
      license='Apache 2.0',
      packages=packages,
      include_package_data=True,
      zip_safe=False,
      install_requires=['distutils'],
)
