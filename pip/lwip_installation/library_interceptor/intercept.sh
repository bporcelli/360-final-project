#!/bin/bash

CWD=$(readlink -f $0)
CWD=$(dirname $CWD)
cd $CWD

LD_PRELOAD=./libdisasm.so.0 ./intercept $1 $2 "65 ff 15 10 00 00 00,cd 80" 35 libc

