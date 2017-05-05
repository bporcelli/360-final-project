#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"

#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

# Get Ubuntu distribution and version
# distribution=`lsb_release -i |gawk '{print $3}'`
# distribution_release=`lsb_release -r |gawk '{print $2}'`
# current_system="$distribution"_"$distribution_release"
# # Decide what libraries to modify based on version (likely only going to support one but...)
# if [[ "$current_system" == "Ubuntu_10.04" ]]; then
# 	libs2intercept=( "/lib/libc.so.6" "/lib/libpthread.so.0" "/lib/tls/i686/cmov/libpthread.so.0" "/lib/tls/i686/cmov/libc.so.6" )
# elif [[ "$current_system" == "Ubuntu_10.10" ]]; then
# 	libs2intercept=( "/lib/libc.so.6" "/lib/libpthread.so.0" )
# elif [[ "current_system" == "Ubuntu_16.04" ]]; then
# 	libs2intercept=( "/lib/i386-linux-gnu/libc.so.6" "/lib/i386-linux-gnu/libpthread.so.0")
# else
# 	echo "[Error] Unsupported Distribution: Unable to Determine Libraries to Intercept"
# 	exit 1
# fi


# WHAT THE INSTALLATION SCRIPT MUST DO:

#####################################
## Install glibc wrapper libraries ##
#####################################
../library/install.sh

##################################################
## Create the untrusted users (PiP section 2.1) ##
##################################################
# Get user running this script (also works if running as sudo)
# realUserName=`who | awk '{print $1}'`
# # Untrusted Userids
# untrusted_id=1004
# untrustedRoot_id=1005
# # Create "untrusted" user (-u sets userid) and a group "untrusted"
# useradd -u $untrusted_id untrusted
# # Modify "untrusted" user (-a adds user to group, -G groups to add to)
# usermod -a -G untrusted $realUserName
# # Create untrusted root user
# useradd -u $untrustedRoot_id untrustedRoot
# # Create "trusted_group"
# sudo groupadd trusted_group
# # Add every user on system other then "untrusted" to the "trusted_group"
# # Cut passwd down to first column (usernames) (seperated by ';'), remove "untrusted" username, add each to "trusted_group"
# cat /etc/passwd|cut -f 1 -d ':'|grep -v untrusted|xargs -n1 -I'{}' bash -c "sudo usermod -a -G trusted_group {}"

###################################################################
## Set permissions on world-executables (PiP sections 2.1 and 5) ##
###################################################################
# Get list of all files on system that have executable bit set for at least others
# Replace '-o+x' with -perm '-a+x' for files executable by user/group/others
# Add '-type f' to narrow search to files (no dirs)
# world_executables=$(find / -perm -o+x)
# Find all world-executables and chmod them to new permission
# find / -perm -o+x -exec chmod *** {} \;

###########################################################################
## Set permissions on world-writable files/dirs (PiP sections 2.1 and 5) ##
###########################################################################
# Get list of all files on system that have write bit set for at least others
# Replace '-o+x' with -perm '-a+x' for files executable by user/group/others
# world_writables=$(find / -perm -o+w)
# Find all world-writables and chmod them to new permission
# find / -perm -o+w -exec chmod *** {} \;


# Not sure what permissions to set the above to

# TODO: set up path to bind our UNIX domain sockets to (see lines 132-134 in lwip_installation/install.sh)
# TODO: generate header file with common variables (see lwip_new/configure.sh, lwip_new/include/common/lwip_common.h.template)
# TODO: build uudo executable with make and add to path (see 98-99, 106 in lwip_installation/install.sh)
# TODO: determine if/where PiP changes the permissions on world-executables/world-writables, and if not, why