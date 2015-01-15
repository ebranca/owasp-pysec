Overflow on posix file date
===========================

Classification
--------------

* **Affected Components** : builtin, os, sys

* **Operating System** : Linux

* **Python Versions** : 2.6.x, 2.7.x, 3.1.x, 3.2.x

* **Reproducible** : Yes


Source code 
--------------------------

```python
import os, sys

testfile = 'TESTFILE'

# Showing stat information of file
stinfo = os.stat('TESTFILE')
print(stinfo)

# Using os.stat to recieve atime and mtime of file
print("access time of TESTFILE: %s" %stinfo.st_atime)
print("modified time of TESTFILE: %s" %stinfo.st_mtime)

# INT is a 32-bit data-type with a ranging from -2^31 (-2,147,483,648) to 2^31-1 (2,147,483,647).
# Clean execution
#os.utime("TESTFILE",(-2147483648, 2147483647))
# Overflow
os.utime("TESTFILE",(-2147483648, 2147483648))

# Showing stat information of file
stinfo = os.stat('TESTFILE')
print(stinfo)

# Using os.stat to recieve atime and mtime of file
print("access time of TESTFILE: %s" %stinfo.st_atime)
print("modified time of TESTFILE: %s" %stinfo.st_mtime)

os.utime("TESTFILE",(1330712280, 1330712292))

# Showing stat information of file
stinfo = os.stat('TESTFILE')
print(stinfo)

# Using os.stat to recieve atime and mtime of file
print("access time of TESTFILE: %s" %stinfo.st_atime)
print("modified time of TESTFILE: %s" %stinfo.st_mtime)

sys.exit()
```


Steps to Produce/Reproduce
--------------------------

To reproduce the problem create a file named 'TESTFILE' and copy the `source code` in a file, then execute the script using the following command syntax:

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

If system or user set numerical date of a file bigger than a 32bit int, python should intercept the operation and prevent a crash.

At the moment if python reads stats of a file having a date that if transformed in numerical value is bigger then maximum 32bit maximum value, it raises a numeric overflow and the the interpreter crashes.

If the script is executed in **Python 2.6** we have:

```python
posix.stat_result(st_mode=33188, st_ino=293602594L, st_dev=2065L, 
st_nlink=1, st_uid=1000, st_gid=1000, st_size=0L, st_atime=1330712280, 
st_mtime=1330712292, st_ctime=1401655733)
access time of TESTFILE: 1330712280.0
modified time of TESTFILE: 1330712292.0
Traceback (most recent call last):
  File "test.py", line 17, in <module>
    os.utime("TESTFILE",(-2147483648, 2147483648))
OverflowError: long int too large to convert to int
```

And if the script is executed in **Python 2.7** or in **Python 3.1** we have:

```python
posix.stat_result(st_mode=33188, st_ino=293602594, st_dev=2065, 
st_nlink=1, st_uid=1000, st_gid=1000, st_size=0, st_atime=1330712280, 
st_mtime=1330712292, st_ctime=1401655733)
access time of TESTFILE: 1330712280.0
modified time of TESTFILE: 1330712292.0
Traceback (most recent call last):
  File "test.py", line 17, in <module>
    os.utime("TESTFILE",(-2147483648, 2147483648))
OverflowError: Python int too large to convert to C long
```

Integers in a 32bit system ranges from -2^31 (-2,147,483,648) to 2^31-1 (2,147,483,647) and python does not check for this condition.

A call setting or reading time of a file between numerical boundaries does not return error

```python
# Clean execution
os.utime("TESTFILE",(-2147483648, 2147483647))
```

But a call that sets time of a file to a value bigger than the maximum is allowed:

```python
# Overflow
os.utime("TESTFILE",(-2147483648, 2147483648))
```

**If the file is read this generates a numeric overflow inside the interpreter.**


Workaround
-----------


We are not aware on any **easy** solution other than implementing strict numeric validation on each operation reading data from files or data from the system as is not implicitly safe.


Secure Implementation
-----------


##### WORK IN PROGRESS


References
-----------

[Python built-in types][01]
[01]:https://docs.python.org/2/library/stdtypes.html


[Python built-in functions][02]
[02]:https://docs.python.org/2/library/functions.html


[Python sys.maxint call][03]
[03]:https://docs.python.org/2/library/sys.html#sys.maxint


[Word Sizes][04]
[04]:http://en.wikipedia.org/wiki/Word_%28computer_architecture%29#Table_of_word_sizes


