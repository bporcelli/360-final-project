#!/bin/bash

##################################################
## Uninstalls untrusted program launcher (runt) ##
##################################################

#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

CWD=$(dirname $0)
cd $CWD

rm -f /bin/runt