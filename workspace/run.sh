#!/bin/bash

echo "Processing Data..."

for i in $@ ;
do
    sed -i "s/\'//g" $i
done
#echo $@

./vga2data.sh $@
echo "Done!"
echo "Processing EPS..."
cd data
exit

./data2eps.sh 
cd ..
echo "Done!"
echo "Processing PDF..."
cd eps
./eps2pdf.sh
cd ..
echo "Done!"
echo "Merging PDF..."
cd pdf
./pdf2merge.sh
cd ..
echo "Done!"
