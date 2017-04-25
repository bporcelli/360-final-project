#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"

# Test to make directories:
# Once we know the specific files and locations to 
# install them we can change these.

mkdir ../objects
mkdir ../include
mkdir ../bin
mkdir ../logs
mkdir ../logs/error_logs
mkdir ../logs/install_logs
mkdir ../utilities




# Get Ubuntu distribution and version
distribution=`lsb_release -i |gawk '{print $3}'`
distribution_release=`lsb_release -r |gawk '{print $2}'`
current_system="$distribution"_"$distribution_release"

# Decide what libraries to modify based on version (likely only going to support one but...)
if [[ "$current_system" == "Ubuntu_10.04" ]]; then
	libs2intercept=( "/lib/libc.so.6" "/lib/libpthread.so.0" "/lib/tls/i686/cmov/libpthread.so.0" "/lib/tls/i686/cmov/libc.so.6" )
elif [[ "$current_system" == "Ubuntu_10.10" ]]; then
	libs2intercept=( "/lib/libc.so.6" "/lib/libpthread.so.0" )
elif [[ "$current_system" == "Ubuntu_11.04" ]]; then
	libs2intercept=( "/lib/i386-linux-gnu/libc.so.6" "/lib/i386-linux-gnu/libpthread.so.0" )
elif [[ "current_system" == "Ubuntu_16.04" ]]; then
	libs2intercept=( "/lib/i386-linux-gnu/libc.so.6" "/lib/i386-linux-gnu/libpthread.so.0")
else
	echo "[Error] Unsupported Distribution: Unable to Determine Libraries to Intercept"
	exit 1
fi

# Get user running this script (also works if running as sudo)
realUserName=`who | awk '{print $1}'`

# Untrusted Userids
untrusted_id=1004
untrustedRoot_id=1005
# Create untrusted user (-u sets userid)
useradd -u $untrusted_id untrusted
# Modify untrusted user (-a adds user to group, -G groups user is in)
usermod -a -G untrusted $realUserName
# Create untrusted root user (?)
useradd -u $untrustedRoot_id untrustedRoot

# WHAT THE INSTALLATION SCRIPT MUST DO:
#	Copy our glibc wrapper library into 'usr/lib/' or '/usr/local/lib'
#	Append the name of our '.so' file to 'etc/ld.so.preload'
#	Call Idconfig(8) to update the cache used by the program loader
#	Create the untrusted users (PiP section 2.1)
#	Set permissions on world-executables (PiP sections 2.1 and 5)
#	Set permissions on world-writable files/dirs (PiP sections 2.1 and 5)


