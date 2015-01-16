Compare decimal and float
=========================


Classification
--------------

* **Affected Components** : builtin compare, decimal

* **Operating System** : Linux

* **Python Versions** : 2.6.x, 2.7.x, 3.1.x, 3.2.x

* **Reproducible** : Yes


Source code 
-----------

```python

from decimal import Decimal

# Should report error as we are comparing FLOAT to DECIMAL that are DIFFERENT TYPES
print("Content of Object1 is FLOAT '1172837167.27'")
print("Content of Object2 is DECIMAL '1172837167.27'")
try:
    x = Decimal("1172837136.0800")
    y = 1172837136.0800
    if y > x:
        print("ERROR: FLOAT is detected as same as DECIMAL")
    else:
        print("ERROR: FLOAT seems comparable with DECIMAL")
except Exception as e:
    print("OK: FLOAT is NOT comparable with DECIMAL")

# Output:
# Python 2.6.5 32bit -- ERROR: FLOAT seems comparable with DECIMAL   (WRONG)
# Python 2.7.4 32bit -- ERROR: FLOAT seems comparable with DECIMAL   (WRONG)
# Python 3.1.2 32bit -- OK: FLOAT is NOT comparable with DECIMAL   (CORRECT)

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

Python internal compare function does not verify if a comparison of two objects is done by using object of the same type. 

In this case python does not know how to compare ```DECIMAL``` and ```FLOATS``` and returns a ```FALSE``` instead of returning an ```Error```.

In this case we have asked python to compare a an object of type ```DECIMAL```:

```python
    x = Decimal("1172837136.0800")
```

with an object of type ```FLOAT```:

```python
    y = 1172837136.0800
```

and to make the comparison we introduced an if condition:

```python

    if y > x:
        print("ERROR: FLOAT is detected as same as DECIMAL")
    else:
        print("ERROR: FLOAT seems comparable with DECIMAL")

```


Python should have strict rules to only allow comparison between objects is aware of but depending on the version of Python we have different behaviors:

* Python 2.6.5 -- ERROR: FLOAT seems comparable with DECIMAL   **(WRONG)**
* Python 2.7.4 -- ERROR: FLOAT seems comparable with DECIMAL   **(WRONG)**

Both python 2.6 and python 2.7 are not able to make the comparison and the 'fail open' logic returns a FALSE that produce the odd situation in which seems that DECIMAL and FLOAT are comparable.

* Python 3.1.2 -- OK: FLOAT is NOT comparable with DECIMAL  **(CORRECT)**

Python 3.1 and newer is able to discriminate between object types and return an error that is intercepted by the ```exception```:

```python
except Exception as e:
    print("OK: FLOAT is NOT comparable with DECIMAL")
```

And therefore a message is printed to state that the comparison failed as expected with an error.

Workaround
----------

Internal function able to properly discriminate between object types are available in Python 3.1 and later but not in any previous version.


Secure Implementation
---------------------


##### WORK IN PROGRESS


References
----------
[Python Built-in types][01]
[01]:https://docs.python.org/2/library/stdtypes.html

[Python Introduction][02]
[02]:https://docs.python.org/2/tutorial/introduction.html

[Python Data Model][03]
[03]:https://docs.python.org/2/reference/datamodel.html

[Python 'decimal' module][04]
[04]:https://docs.python.org/2/library/decimal.html


