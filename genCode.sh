#!/bin/bash

mkdir codeSet
for file in $(ls code/)
do
	sed  "1i\\#include\"include/libsy.h\"" code/${file} > codeSet/$(basename -s .sy ${file}).c
	sed -i "s/getInt/getint/g" codeSet/$(basename -s .sy ${file}).c
done
