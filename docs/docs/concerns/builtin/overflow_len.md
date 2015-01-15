Overflow in len function
========================

Classification
--------------------------

* **Affected Components** : builtin

* **Operating System** : Linux

* **Python Versions** : 2.6.x, 2.7.x, 3.1.x, 3.2.x

* **Reproducible** : Yes


Source code 
--------------------------

```python
class A(object):
    def __len__(self): 
        return 100 ** 100

class B(object):
    def __len__(self): 
        return 2L

class C:
    def __len__(self): 
        return 100 ** 100

class D:
    def __len__(self): 
        return 2L

try:
    len(A())
    print """OK: 'class A(object)' with 'return 100 ** 100' - len calculated"""
except Exception as e:
    print """KO: 'class A(object)' with 'return 100 ** 100' - len raise Error: """ + repr(e,)

try:
    len(B())
    print """OK: 'class B(object)' with 'return 2L' - len calculated"""
except Exception as e:
    print """KO: class B(object) with return 2L - len raise Error: """ + repr(e,)

try:
    len(C())
    print """OK: 'class C' with 'return 100 ** 100' - len calculated"""
except Exception as e:
    print """KO: 'class C' with 'return 100 ** 100' - len raise Error: """ + repr(e,)

try:
    len(D())
    print """OK: 'class C' with 'return 2L' - len calculated"""
except Exception as e:
    print """KO: 'class C' with 'return 2L' - len raise Error: """ + repr(e,)
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

The source code tets the ability of python to check the length of an object.

When the source code is executed 

```python
$ python -OOBRttu test.py 
```

we have the ***same results both python 2.6.x and 2.7.x*** as follow:

```python
KO: 'class A(object)' with 'return 100 ** 100'
Error: OverflowError('long int too large to convert to int',)

OK: 'class B(object)' with 'return 2L' - len calculated

KO: 'class C' with 'return 100 ** 100'
Error: TypeError('__len__() should return an int',)

KO: 'class C' with 'return 2L'
Error: TypeError('__len__() should return an int',)
```

in this case the ```len()``` function in python does not check for the legth of the object and does not use "python int objects" (unlimited) and this can cause an ```Overflow``` error as the object may contain the actual `.length` property.

The reason of this is beacuse ```len(obj)``` is implemented using PyObject_Size(), which in turn it stores the result into a Py_ssize_t, and this object is limited to sys.maxsize (```2**31-1``` for 32bit or ```2**63-1``` for 64bit systems).

And when the length of the object is bigger then the maximum size of an **integer** object in python, the type of the object changes to **long**.

Even this condition is not checked in the core libraries therefore an unexpected ```TypeError``` is generated.



Workaround
-----------


We are not aware on any **easy** solution other than writing a custom library to handle the described cases.


Secure Implementation
-----------


##### WORK IN PROGRESS


References
-----------

[Python built-in functions][01]
[01]:https://docs.python.org/2/library/functions.html


[Python Classes][02]
[02]:https://docs.python.org/2/tutorial/classes.html


[Python bug 12159][03]
[03]:http://bugs.python.org/issue12159


[Python bug 15718][04]
[04]:http://bugs.python.org/issue15718


[Python bug 21444][05]
[05]:http://bugs.python.org/issue21444



