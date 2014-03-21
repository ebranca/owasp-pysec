#!/usr/bin/env python

from distutils.core import setup, Extension

packages = [
    'pysec',
    'pysec.core',
    'pysec.io',
    'pysec.kv',
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
    Extension('pysec.core.memory', ['pysec/core/memory.c'])
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