#!/bin/bash

CWD=$(dirname $0)
cd $CWD


make clean
./configure.sh
sudo make install

