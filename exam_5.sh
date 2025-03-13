#!/bin/bash

i=0
while [ ${i} -le 20 ]
do
	sed "s/REPLACE/${i}/g" ./origin/code/${i}.c > ./result/code/${i}.c
	let i=i+1
done
