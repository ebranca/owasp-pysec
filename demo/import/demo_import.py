#!/usr/bin/python2.7 -OOBRtt
import os
import sys

from pysec import load, tb

tb.set_excepthook(tb.short_tb)


print "Modules tab path:",
path = os.path.abspath(raw_input())

print "Loading modules' tab..."
load.load_tab(path)


print "Loading 'docopt'..."
docopt = load.importlib('docopt')

print "Loading 'paypal'..."
paypal = load.importlib('paypal', version=(1, 0, 3))



