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
elif [[ "current_system" == "Ubuntu_16.04" ]]; then
	libs2intercept=( "/lib/i386-linux-gnu/libc.so.6" "/lib/i386-linux-gnu/libpthread.so.0")
else
	echo "[Error] Unsupported Distribution: Unable to Determine Libraries to Intercept"
	exit 1
fi


# WHAT THE INSTALLATION SCRIPT MUST DO:

########################################################################
## Copy our glibc wrapper library into 'usr/lib/' or '/usr/local/lib' ##
########################################################################
wrapper_loc=/somewhere/over/the/rainbow
wrapper_dest=/usr/lib
sudo cp wrapper_loc wrapper_dest

##############################################################
## Append the name of our '.so' file to 'etc/ld.so.preload' ##
##############################################################
# Enter the names of overriding libraries (.o files) in /etc/ld.so.preload
# These "preloading" libraries will take precedence over the standard set.
# It contains names of libraries to be loaded, separated by white spaces or `:'.
libs_appended=0
for lib in "libName1.o" "libname2.o" "libname3.o"
do
	if [[ $libs_appended == 0 ]]; then
		# Overwrites the file
		echo "$lib" > /etc/ld.so.preload
	else
		# Appends to the file
		echo ":$lib" >> /etc/ld.so.preload
	fi
	let libs_appended++
done

#####################################################################
## Call ldconfig(8) to update the cache used by the program loader ##
#####################################################################
	# -v: verbose
	# -C cache: Use cache instead of /etc/ld.so.cache
	# -f conf: Use conf instead of /etc/ld.so.conf
	# -n: Only process given directories and don't rebuild the cache
sudo ldconfig -n lib_dir  # (this is what the article suggested, but -n doesn't rebuild cache, so not sure)

##################################################
## Create the untrusted users (PiP section 2.1) ##
##################################################
# Get user running this script (also works if running as sudo)
realUserName=`who | awk '{print $1}'`
# Untrusted Userids
untrusted_id=1004
untrustedRoot_id=1005
# Create "untrusted" user (-u sets userid) and a group "untrusted"
useradd -u $untrusted_id untrusted
# Modify "untrusted" user (-a adds user to group, -G groups to add to)
usermod -a -G untrusted $realUserName
# Create untrusted root user
useradd -u $untrustedRoot_id untrustedRoot
# Create "trusted_group"
sudo groupadd trusted_group
# Add every user on system other then "untrusted" to the "trusted_group"
# Cut passwd down to first column (usernames) (seperated by ';'), remove "untrusted" username, add each to "trusted_group"
cat /etc/passwd|cut -f 1 -d ':'|grep -v untrusted|xargs -n1 -I'{}' bash -c "sudo usermod -a -G trusted_group {}"

###################################################################
## Set permissions on world-executables (PiP sections 2.1 and 5) ##
###################################################################
# Get list of all files on system that have executable bit set for at least others
# Replace '-o+x' with -perm '-a+x' for files executable by user/group/others
# Add '-type f' to narrow search to files (no dirs)
world_executables=$(find / -perm -o+x)
# Find all world-executables and chmod them to new permission
# find / -perm -o+x -exec chmod *** {} \;

###########################################################################
## Set permissions on world-writable files/dirs (PiP sections 2.1 and 5) ##
###########################################################################
# Get list of all files on system that have write bit set for at least others
# Replace '-o+x' with -perm '-a+x' for files executable by user/group/others
world_writables=$(find / -perm -o+w)
# Find all world-writables and chmod them to new permission
# find / -perm -o+w -exec chmod *** {} \;


# Not sure what permissions to set the above to
