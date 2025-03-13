#!/bin/bash

mkdir codeSet
i=1
while [ $i -le 10 ]
do
	sed  "1i\\#include\"include/libsy.h\"" code/code${i}.sy > codeSet/code${i}.c
	sed -i "s/getInt/getint/g" codeSet/code${i}.c
	let i=i+1
done
sed  "1i\\#include\"include/libsy.h\"" code/wa.sy > codeSet/wa.c
sed -i "s/getInt/getint/g" codeSet/wa.c
