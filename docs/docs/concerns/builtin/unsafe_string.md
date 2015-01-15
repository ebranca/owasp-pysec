Unsafe String interpretation if using input() function
=======================================================

Classification
--------------------------

* **Affected Components** : builtins

* **Operating System** : Linux

* **Python Versions** : 2.6.x, 2.7.x

* **Reproducible** : Yes


Source code 
--------------------------

```python
Secret = "A SECRET DATA"
Public = "a BANANA"

value = input("Please enter your age ")
print "There are",value,
print "monkeys looking for",Public
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

The script will ask the user to provide a number, and if the user provides **ONLY** a number then nothing happens.

```
python -OOBRtt test.py
Please enter your age 32
There are 32 monkeys looking for a BANANA
```

But if the user provides something different, for example a python command as ```dir()```, the string is interpreted and executed:

```
python -OOBRtt test.py
Please enter your age dir()
There are ['Public', 'Secret', '__builtins__', '__doc__', '__file__', '__name__', '__package__'] monkeys looking for a BANANA
```
In this case using ```dir()``` allow us to see “most” of the attributes of an object.

Is also possible to provie the name of a variable, in this case we provide ```SECRET``` as this is the name of the variable that should not be accessible.

```
python -OOBRtt test.py
Please enter your age Secret
There are A SECRET DATA monkeys looking for a BANANA
```

***What you type as input is interpreted through an expression and the result is saved into your target variable with no control or limits.***

Workaround
-----------


We are not aware on any **easy** solution other than trying to avoid using the function ```'input'``` in cases like the one examined.



Secure Implementation
-----------


##### WORK IN PROGRESS


References
-----------

[Python builtins][01]
[01]:https://docs.python.org/2/library/functions.html




