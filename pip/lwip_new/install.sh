#!/bin/bash

CWD=$(dirname $0)
cd $CWD


make clean			# remove existing binaries and lwip_common.h
./configure.sh		# generate include/common/lwip_common.h
sudo make install   # build with customized lwip_common.h

