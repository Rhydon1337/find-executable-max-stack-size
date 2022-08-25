# find-binary-max-stack-size

## TL;DR 
Find binary max stack size using IDA python

Tested on x86 and x64 binaries, it supposes to work on all architectures that are supported by IDA.

## How its works
1. Create a Tree that links all function calls like a graph
2. Get all the functions that are root nodes in the Tree
3. Find for each root function its stack size
   * linking all parents in order to avoid recursion in one of the child nodes
   * the calculation is done using IDA python too - the sum of idc.get_frame_size on every function

## Usage
Open IDA with your binary. When IDA finished to parse it, go to:

File -> Script file -> {path_to_main.py}

## Limitations
1. There is no support on recursion the code will detect it and skip it
2. *The code is written in Python3. Therefore, you should only run it on IDA that comes with python3*

DONE!!!
