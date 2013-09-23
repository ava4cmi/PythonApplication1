#!/bin/bash

n=`wc -l $1| cut -d' ' -f1`

for i in $@ ;
do
    basename=`echo -n $i | awk -F"." '{print $1}'`
    all="$all $basename"
done

#for ((i=1;i<=$n;i++));
for ((i=1;i<=$n;i++));
do
    aux=`head -n$i $1 | tail -n1 | awk -F"," '{print NF}'`
    title=`head -n$i $1 | tail -n1 | awk -F"'" '{print $1}' | cut -d[ -f1 | cut -d: -f1-2 `
    name=`head -n$i $1 | tail -n1 | cut -d' ' -f1`
    tmp=
    echo "#$title" >> data/$name.data
    echo "Attributes $all" >> data/$name.data
    
    for ((j=1;j<=$aux;j++));
	do
		let impar=`expr $j % 2`
        if [ $impar -eq 1 ];
        then
            if [ $j -lt $aux ];
            then
                let jj=$j+1
                counter=1
                aux22=
                for k in $@;
                do
                    if [ $counter -eq 1 ];
                    then
                        aux1=`head -n$i $k | tail -n1 | cut -d, -f$j,$jj | cut -d[ -f2 |cut -d] -f1`
                    fi
                    if [ $counter -ne 1 ] && [ $counter -ne $# ];
                    then
	                    aux2=`head -n$i $k | tail -n1 | cut -d, -f$jj | cut -d] -f1`
                        aux22="$aux22 $aux2"
                    fi
                    if [ $counter -eq $# ];
                    then
                        aux3=`head -n$i $k | tail -n1 | cut -d, -f$jj | cut -d] -f1`
                    fi
                    (( counter++ ))
                done
		        tmp="${aux1} ${aux22} ${aux3}"
                echo $tmp >> data/$name.data
            fi
        fi
	done
done
