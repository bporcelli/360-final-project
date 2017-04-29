#!/bin/bash

CWD=$(dirname $0)
cd $CWD

#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

###############################
## Reset 'etc/ld.so.preload' ##
###############################
> "/etc/ld.so.preload"

######################################################
## Remove our glibc wrapper libraries from usr/lib/ ##
######################################################
LIB_DIR="/usr/lib/"
LIBS=("libwrap.so")
rm -f ${LIBS[@]/#/$LIB_DIR}

#####################################################################
## Call ldconfig(8) to update the cache used by the program loader ##
#####################################################################
ldconfig