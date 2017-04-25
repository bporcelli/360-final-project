#!/bin/bash

cd ~/lwip_installation/lwip_installer/library_interceptor/
make clean
make replace 

cd ../daemon/
restoreLib 
make clean
make

cd ../uudo/
make clean
make

cd ../redirectHelper/
make clean
make
replaceLib


