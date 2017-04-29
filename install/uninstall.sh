#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"

#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

#######################################
## Uninstall glibc wrapper libraries ##
#######################################
../library/uninstall.sh