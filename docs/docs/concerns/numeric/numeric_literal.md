Numeric literal and whitespaces
===============================

Classification
--------------------------

* **Affected Components** : builtin

* **Operating System** : Linux

* **Python Versions** : 2.6.x, 2.7.x

* **Reproducible** : Yes


Source code 
--------------------------

```python
try:
    x = int('+ 0')
    print """OK: int('+ 0') - string converted"""
except Exception as e:
    print """KO: int('+ 0') - string not converted raise Error: """ + repr(e,)

try:
    y = float('+0.0')
    print """OK: float('+0.0') - string converted"""
except Exception as e:
    print """KO: float('+0.0') - string not converted raise Error: """ + repr(e,)

try:
    z = float('+ 0.0')
    print """OK: float('+ 0.0') - string converted"""
except Exception as e:
    print """KO: float('+ 0.0') - string not converted raise Error: """ + repr(e,)

try:
    a = int('2 3')
    print """OK: int('2 3') - string converted"""
except Exception as e:
    print """KO: int('2 3') - string not converted raise Error: """ + repr(e,)

try:
    import string
    b = string.atof("-2")
    print """OK: string.atof("-2") - string converted"""
except Exception as e:
    print """KO: string.atof("-2") - string not converted raise Error: """ + repr(e,)

try:
    import string
    c = string.atof("- 2")
    print """OK: string.atof("- 2") - string converted"""
except Exception as e:
    print """KO: string.atof("- 2") - string not converted raise Error: """ + repr(e,)

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

Tests using ***Python 2.6*** generated the following results:

1. OK: int('+ 0') - string converted
2. OK: float('+0.0') - string converted
3. KO: float('+ 0.0') - string not converted raise Error: ValueError('invalid literal for float(): + 0.0',)
4. KO: int('2 3') - string not converted raise Error: ValueError("invalid literal for int() with base 10: '2 3'",)
5. OK: string.atof("-2") - string converted 
6. KO: string.atof("- 2") - string not converted raise Error: ValueError('invalid literal for float(): - 2',)

And tests using ***Python 2.7*** generated the following results:

1. OK: int('+ 0') - string converted
2. OK: float('+0.0') - string converted
3. KO: float('+ 0.0') - string not converted raise Error: ValueError('could not convert string to float: + 0.0',)
4. KO: int('2 3') - string not converted raise Error: ValueError("invalid literal for int() with base 10: '2 3'",)
5. OK: string.atof("-2") - string converted 
6. KO: string.atof("- 2") - string not converted raise Error: ValueError('could not convert string to float: - 2',)


In python whitespace between sign and digits should be always discarded but is not the case as the behaviour changes depending on the object type.

For numbers expressed as ```int``` whitespace is discarded while for numbers expressed as ```float``` whitespace is **NOT** discarded.

Also to note that whitespace between integers like ```(2 3)``` never works regardless of the object type.


Workaround
-----------


We are not aware on any **easy** solution other than trying to avoid using **numeric literals** for cases like the one examined, instead the code should handle specific implementation and stripe leading and trailing whitespaces and unprintable characters by default.



Secure Implementation
-----------


##### WORK IN PROGRESS


References
-----------

[Python builtin types][01]
[01]:https://docs.python.org/2/library/stdtypes.html


[Python builtin functions][02]
[02]:https://docs.python.org/2/library/functions.html


[Python bug 14252][03]
[03]:http://bugs.python.org/issue620181


