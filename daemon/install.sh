#!/bin/bash

######################################
## Installs trusted helper (daemon) ##
######################################

#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

CWD=$(dirname $0)
cd $CWD

###############################
## Build executable 'daemon' ##
###############################
make clean all

###############################
## Move to /sip/executables/ ##
###############################
mv daemon /sip/executables/daemon