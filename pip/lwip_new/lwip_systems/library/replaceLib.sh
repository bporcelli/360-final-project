#!/bin/sh


if [ $(cat libextlib.so.1|wc -c) = 0 ]; then
	echo "0 library size"
else
sudo ~/restoreLib
sudo rm /lib/libextlib.so.1
sudo cp libextlib.so.1 /lib/libextlib.so.1
sudo rm /usr/lib/libextlib.so.1
sudo cp libextlib.so.1 /usr/lib/libextlib.so.1
sudo ~/replaceLib
fi

