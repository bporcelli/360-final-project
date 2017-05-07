#!/bin/bash

CWD=$(dirname $0)
cd $CWD

# Create a configuration header file from the template
INCL="../common/include"
TEMPLATE="$INCL/common.h.template"
CONFIG="$INCL/common.h"

cp $TEMPLATE $CONFIG

# Replace all occurrences of first arg with second arg in $CONFIG.
function replaceEntry {
	sed -i "s/$1/$2/g" "$CONFIG" # -i flag -> edit file in place
}

# Get user name of person running script
realUserName=`who | awk '{print $1}'`

# Add this user's username to the header
replaceEntry "BASH_CONFIG_REAL_USERNAME" "\"$realUserName\""
# Add this user's UserID to the header
replaceEntry "BASH_CONFIG_REAL_USER_UID" `cat /etc/passwd|grep "$realUserName:"|cut -f 3 -d ":"`
# Add the untrusted user's UserID to the header
replaceEntry "BASH_CONFIG_UNTRUSTED_UID" `cat /etc/passwd|grep "untrusted:"|cut -f 3 -d ":"`
# Add the trusted GroupID to the header
replaceEntry "BASH_CONFIG_TRUSTED_GID" `cat /etc/group|cut -d ":" -f 1,3|grep trusted_group|cut -d ":" -f 2`