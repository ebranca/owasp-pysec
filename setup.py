#!/usr/bin/env python

from distutils.core import setup, Extension

packages = [
    'pysec',
    'pysec.core',
    'pysec.io',
    'pysec.kv',
]


exts = [
    Extension('pysec.core.unistd', ['pysec/core/unistd.c'], libraries=['crypt']),
    Extension('pysec.core.memory', ['pysec/core/memory.c'])
]

setup(name='pysec',
      version='0.0',
      description='PySec is a set of tools for secure application development under Linux',
      author='Python security project\'s team',
      url='http://www.pythonsecurity.org/',
      packages=packages,
      ext_modules=exts
     )
