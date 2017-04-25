#!/bin/bash


if [[ $1 == "/lwip/opendb/"* ]]; then
	path=$1
else
	path="/lwip/opendb/$1.openTrace"
fi

grep "^A: RW " $path |cut -f 3 -d " "|sort|uniq > /tmp/rw

grep "^A: R " $path |gawk '{print $3}'|sort|uniq > /tmp/ronly
grep "^A:  W" $path |gawk '{print $3}'|sort|uniq > /tmp/wonly
comm /tmp/ronly /tmp/wonly -12 >> /tmp/rw

sort /tmp/rw > /tmp/rw0
mv /tmp/rw0 /tmp/rw


grep "regarded as explicit" $path |cut -f 4 -d " "|sort|uniq > /tmp/explicit

comm /tmp/rw /tmp/explicit -23 
