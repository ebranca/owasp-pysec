Missing checks for invalid write to closed fd
==============================================

Classification
--------------------------

* **Affected Components** : builtin, sys, io

* **Operating System** : Linux

* **Python Versions** : 2.6.x, 2.7.x

* **Reproducible** : Yes


Source code 
--------------------------

```python
import sys
import io

fd = io.open(sys.stdout.fileno(), 'wb')
fd.close()

try:
    sys.stdout.write("test for error")
except Exception:
    raise

sys.exit(0)
```


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

The test code is executing an operation that is logically incorrect and should not be allowed by default.

First we open allocate a file descriptor for a write operation hen we close the file descriptor just opened.

```
fd = io.open(sys.stdout.fileno(), 'wb')
fd.close()
```

Then we try to write the string "test for error" into the file descriptor that should receive the stream from standard output.

```
try:
    sys.stdout.write("test for error")
except Exception:
    raise
```

This operation is semantically correct but is logically broken as the standard output was directed to a file descriptor that we just closed. As a result this is an illegal operation as we are trying to write something into an object that does not exist into the operating system and cannot read from standard input.

```
close failed in file object destructor:
sys.excepthook is missing
lost sys.stderr
```

This is happening because the code is trying to write a non zero amount of output to something that never reads from standard input. 

In this case the file descriptor has been closed and nothing can be sent, but python has no controls for this kind of actions and returns a system error.


Workaround
-----------


We are not aware on any **easy** solution other than trying to avoid output redirection in cases like the one examined.



Secure Implementation
-----------


##### WORK IN PROGRESS


References
-----------

[Python sys module][01]
[01]:https://docs.python.org/2/library/sys.html


[Python io module][02]
[02]:https://docs.python.org/2/library/io.html


[Python os module][03]
[03]:https://docs.python.org/2/library/os.html


[Python builtin open][04]
[04]:https://docs.python.org/2/library/functions.html#open



