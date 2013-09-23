#!/bin/bash

echo "Processing Data..."
a=( 150 323 837 )
for i in "${a[@]}";
do
    echo $i
    if [ $i -eq 150 ];
    then
	a1=`grep $i $1 | sed "0,/RE/s/,//" | sed "0,/RE/s/,//"`
	sed -i "/$i/d" $1
	echo $a1
        echo $a1 >> $1
	a2=`grep $i $2 | sed "0,/RE/s/,//" | sed "0,/RE/s/,//"`
	sed -i "/$i/d" $2
	echo $a2
        echo $a2 >> $2
	a3=`grep $i $3 | sed "0,/RE/s/,//" | sed "0,/RE/s/,//"`
	sed -i "/$i/d" $3
	echo $a3
        echo $a3 >> $3
    else
        b1=`grep $i $1 | sed "0,/RE/s/,//"`
	sed -i "/$i/d" $1
	echo $b1
        echo $b1 >> $1
        b2=`grep $i $2 | sed "0,/RE/s/,//"`
	sed -i "/$i/d" $2
	echo $b2
        echo $b2 >> $2
	b3=`grep $i $3 | sed "0,/RE/s/,//"`
	sed -i "/$i/d" $3
	echo $b3
        echo $b3 >> $3
    fi
done

sed -i "s/'//g" $1
sed -i "s/'//g" $2
sed -i "s/'//g" $3

echo "Done!"
