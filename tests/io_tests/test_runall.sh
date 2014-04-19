#!/bin/bash
# Simple script to load python files from a folder and execute them
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

for test_py in `(ls $DIR/*.py)`
do
    python $test_py
done