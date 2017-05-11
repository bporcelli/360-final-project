#!/bin/bash

################################################
## Installs untrusted program launcher (runt) ##
################################################

#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

CWD=$(dirname $0)
cd $CWD

#############################
## Build executable 'runt' ##
#############################
make clean all

######################
## Make setuid-root ##
######################
chmod +s runt

###############################
## Move to /sip/executables/ ##
###############################
mv runt /sip/executables/runt

#################
## Add to PATH ##
#################
ln -sf /sip/executables/runt /bin/runt