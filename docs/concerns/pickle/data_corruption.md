Possible data corruption using pickle
=====================================

Classification
--------------------------

* **Affected Components** : pickle

* **Operating System** : Linux

* **Python Versions** : 2.6.x, 2.7.x

* **Reproducible** : Yes


Source code 
--------------------------

```python
import os
import pickle
import sys
import traceback

random_string = os.urandom(int(2147483648))
print ("STRING-LENGTH-1=%r") % (len(random_string))

fout = open('test.pickle', 'wb')

try:
    pickle.dump(random_string, fout)
except Exception as e:
    print "###### ERROR-WRITE ######"
    print sys.exc_info()[0]
    raise

fout.close()

fin = open('test.pickle', 'rb')
try:
    random_string2 = pickle.load(fin)
except Exception as e:
    print "###### ERROR-READ ######"
    print sys.exc_info()[0]
    raise

print ("STRING-LENGTH-2=%r") % (len(random_string2))
print random_string == random_string2

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

Executing the code using an object within the 32bit limit does not generate error.

pickle on  ```debian 7 x64```

LIMIT = 2147483648 -1 = 2147483647 (32bit integer object)

TEST WITH STRING SIZE "2147483647" 


Code output:

```
STRING-LENGTH-1=2147483647
STRING-LENGTH-2=2147483647
True
```

But if we use an object bigger than a 32bit object we have an unexpected error.

```
STRING-LENGTH-1=2147483648
###### ERROR-WRITE ######
<type 'exceptions.MemoryError'>
Traceback (most recent call last):
  File "test.py", line 12, in <module>
    pickle.dump(random_string, fout)
  File "/usr/lib/python2.7/pickle.py", line 1370, in dump
    Pickler(file, protocol).dump(obj)
  File "/usr/lib/python2.7/pickle.py", line 224, in dump
    self.save(obj)
  File "/usr/lib/python2.7/pickle.py", line 286, in save
    f(self, obj) # Call unbound method with explicit self
  File "/usr/lib/python2.7/pickle.py", line 488, in save_string
    self.write(STRING + repr(obj) + '\n')
MemoryError
```

The fact that there is an unexpected error means that if an object is created and dumped to disk, then read again by pickle, there is a strong possibility that the data stream will be truncated without warning at a size compatible with 32bit systems ***even in 64bit systems*** leading to significant data corruption.


Workaround
-----------


We are not aware on any **easy** solution other than trying to avoid using ```'pickle'``` in cases like the one examined.



Secure Implementation
-----------


##### WORK IN PROGRESS


References
-----------

[Python pickle][01]
[01]:https://docs.python.org/2/library/pickle.html


