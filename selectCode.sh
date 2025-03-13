#!/bin/bash

rm -f testfile.c
touch testfile.c
ln -s testfile.c codeSet/$1.c
gcc -I./include/ testfile.c -o test.out
