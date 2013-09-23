#!/bin/bash

n=`wc -l $1| cut -d' ' -f1`

for ((i=1;i<=1;i++));
do
	aux=`head -n$i $1 | tail -n1 | awk -F"'" '{print NF}'`
    name=`head -n$i $1 | tail -n1 | cut -d: -f1`
	tmp=
    for ((j=1;j<=$aux;j++));
	do
		let impar=`expr $j % 2`
        if [ $impar -eq 1 ];
        then
            if [ $j -lt $aux ];
            then
                out=`head -n$i $1 | tail -n1 | cut -d, -f$j | cut -d[ -f2 |cut -d] -f1`
		        tmp=$tmp$out
            fi
        fi
	done
    echo $tmp>> $name.data
    echo "tmp= "$tmp
    tmp2=
    for ((k=1;k<=$aux;k++));
	do
		let impar2=`expr $k % 2`
        if [ $impar2 -eq 1 ];
        then
            if [ $k -lt $aux ];
            then
                let kk=$k+1
                aux1=`head -n$i $1 | tail -n1 | cut -d, -f$kk | cut -d[ -f2 |cut -d] -f1`
                out1=$out1$aux1
        		aux2=`head -n$i $2 | tail -n1 | cut -d, -f$kk | cut -d] -f1`
                out2=$out2$aux2
	        	aux3=`head -n$i $3 | tail -n1 | cut -d, -f$kk | cut -d] -f1`
                out3=$out3$aux3
            fi
        fi
	done
    echo $out1 >> $name.data
    echo $out2 >> $name.data
    echo $out3 >> $name.data
done
