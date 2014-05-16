OWASP Python Security Project - PySec
===========
Python Security is a free, open source, OWASP project that aims at creating a hardened version of python that makes it easier for security professionals and developers to write applications more resilient to attacks and manipulations.

The project is designed to explore how web applications can be developed in python by approaching the problem from three different angles:

+ Security in python: white-box analysis, structural and functional analysis
+ Security of python: black-box analysis, identify and address security-related issues
+ Security with python: develop security hardened python suitable for high-risk and high-security environments

Prerequisites
-------------

+ gcc, g++, make
	- ubuntu -> sudo apt-get install gcc g++ make
	- debian -> apt-get install gcc g++ make (as root)
+ build-essential
	- ubuntu -> sudo apt-get install build-essential
	- debian -> apt-get install build-essential (as root)
+ python-dev
    - ubuntu -> sudo apt-get install python-dev
    - debian -> apt-get install python-dev (as root)
+ zlib
	- ubuntu -> sudo apt-get install  zlib1g-dev

### Optional ###

+ [Kyoto Cabinet](http://fallabs.com/kyotocabinet/pkg/kyotocabinet-1.2.76.tar.gz "Kyoto Cabinet")
+ [Kyoto Cabinet for Python 2.x](http://fallabs.com/kyotocabinet/pythonlegacypkg/kyotocabinet-python-legacy-1.18.tar.gz "Kyoto Cabinet for Python 2.7")


Install
-------

    git clone https://github.com/ebranca/owasp-pysec.git
    cd owasp-pysec/
    python2.7 setup.py install
    

Test
----

    cd tests/
    python runall.py


Optional
--------

### Kyoto Cabinet

    wget http://fallabs.com/kyotocabinet/pkg/kyotocabinet-1.2.76.tar.gz
    tar zxvf kyotocabinet-1.2.76.tar.gz
    cd kyotocabinet-1.2.76/
    ./configure
    make
	make check
	make install

### Kyoto Cabinet for Python 2.7
	
	wget http://fallabs.com/kyotocabinet/pythonlegacypkg/kyotocabinet-python-legacy-1.18.tar.gz
	tar zxvf kyotocabinet-python-legacy-1.18.tar.gz
	cd kyotocabinet-python-legacy-1.18/
	python setup.py install
	ln -s /usr/local/lib/libkyotocabinet.so* /usr/lib/


Links
-----
+ [Main site](http://pythonsecurity.org "Python Security")
+ [OWASP Page](https://www.owasp.org/index.php/OWASP_Python_Security_Project "OWASP Python Security Project")
+ [Github Repository](https://github.com/ebranca/owasp-pysec "PySec Github")
