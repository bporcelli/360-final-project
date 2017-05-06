#!/bin/bash

CWD=$(dirname $0)
cd $CWD

# Create a configuration header file from the template
cp include/common/lwip_common.h.template include/common/lwip_common.h
configFile="include/common/lwip_common.h"
TFILE="/tmp/out.tmp.$$" # Not sure what this is for

# For replacing entries in the configuration file with provided values
function replaceEntry {
	sed "s/$1/$2/g" "$configFile" > $TFILE && mv $TFILE "$configFile" # replace all occurrences of first arg with second arg in $configFile
}

# Get user name of person running script
realUserName=`who | awk '{print $1}'`
# Or (As in the original):
# realUserName=`whoami`
# if [[ $realUserName == "root" ]]; then
#   realUserName=$SUDO_USER
# fi

# Add this user's username to the header
replaceEntry "BASH_CONFIG_REAL_USERNAME" "\"$realUserName\""
# Add this user's UserID to the header
replaceEntry "BASH_CONFIG_REAL_USER_UID" `cat /etc/passwd|grep "$realUserName:"|cut -f 3 -d ":"`
# Add the untrusted user's UserID to the header
replaceEntry "BASH_CONFIG_UNTRUSTED_UID" `cat /etc/passwd|grep "untrusted:"|cut -f 3 -d ":"`
# Add the utrusted root user's UserID to the header
replaceEntry "BASH_CONFIG_UNTRUSTEDROOT_UID" `cat /etc/passwd|grep "untrustedRoot:"|cut -d ":" -f 3`
# Add the trusted GroupID to the header
replaceEntry "BASH_CONFIG_TRUSTED_GID" `cat /etc/group|cut -d ":" -f 1,3|grep trusted_group|cut -d ":" -f 2`

# Running on linux (perhaps not needed)
replaceEntry "BASH_CONFIGURE_OS" "OS_LINUX"
