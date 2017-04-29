#!/bin/bash

CWD=$(dirname $0)
cd $CWD


cp include/common/lwip_common.h.template include/common/lwip_common.h
TFILE="/tmp/out.tmp.$$"
configFile="include/common/lwip_common.h"


function replaceEntry {
	sed "s/$1/$2/g" "$configFile" > $TFILE && mv $TFILE "$configFile" # replace all occurrences of first arg with second arg in $configFile
}


realUserName=`whoami`
if [[ $realUserName == "root" ]]; then
  realUserName=$SUDO_USER
fi

replaceEntry "BASH_CONFIGURE_REAL_USERNAME" "\"$realUserName\""

replaceEntry "BASH_CONFIGURE_REAL_USER_UID" `cat /etc/passwd|grep "$realUserName:"|cut -d ":" -f 3`

replaceEntry "BASH_CONFIGURE_UNTRUSTED_UID" `cat /etc/passwd|grep "untrusted:"|cut -d ":" -f 3`

new="`cat /etc/passwd | awk 'BEGIN {FS=":";ORS=""};{print $3 ", /*" $1 "*/ \\\\\\\\\\\\\\n "}' |grep -v "#" | grep -v "untrusted"`"
old=BASH_CONFIGURE_TRUSTED_USERIDS
sed "s|$old|$new|g" "$configFile" > $TFILE && mv $TFILE "$configFile"


replaceEntry "BASH_CONFIGURE_TRUSTED_GID" `cat /etc/group|cut -d ":" -f 1,3|grep trusted_group|cut -d ":" -f 2`

replaceEntry "BASH_CONFIGURE_UNTRUSTED_UID" `cat /etc/passwd|grep "untrusted:"|cut -d ":" -f 3`

replaceEntry "BASH_CONFIGURE_UNTRUSTEDROOT_UID" `cat /etc/passwd|grep "untrustedRoot:"|cut -d ":" -f 3`


OS=`uname`
if [[ $OS == "FreeBSD" ]]; then
    replaceEntry "BASH_CONFIGURE_OS" "LWIP_OS_BSD"
else
    replaceEntry "BASH_CONFIGURE_OS" "LWIP_OS_LINUX"
fi
