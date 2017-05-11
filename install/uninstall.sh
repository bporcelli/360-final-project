#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"

#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

#######################################
## Uninstall glibc wrapper libraries ##
#######################################
../library/uninstall.sh


########################
## Uninstall launcher ##
########################
../launcher/uninstall.sh


##############################
## Remove files/directories ##
##############################

# Root
sudo rm -rf /sip

# Daemon communication path
sudo rm -rf ~/sip_daemon