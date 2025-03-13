#!/bin/bash

if [ $# -eq 0 ]
then
	cat stderr.txt
elif [ $# -eq 1 ]
then 
	sed -n "$1,\$p" stderr.txt
else
	last=$[$2-1]
	sed -n "$1,${last}p" stderr.txt
fi
