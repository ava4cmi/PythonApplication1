#!/bin/bash

n=`wc -l $1| cut -d' ' -f1`
echo $n

for ((i=1;i<=n;i++));
do
	head -n$i $1 | tail -n1 >> tmp; 
	head -n$i $2 | tail -n1 >> tmp; 
	head -n$i $3 | tail -n1 >> tmp; 
done

