#!/bin/bash

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"

#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

##################################################
## Create the untrusted users (PiP section 2.1) ##
##################################################

# Get user running this script (also works if running as sudo)
realUserName=`who | awk '{print $1}'`

# Untrusted Userids
untrusted_id=1004

# Create "untrusted" user (-u sets userid) and a group "untrusted"
useradd -u $untrusted_id untrusted
# Modify "untrusted" user (-a adds user to group, -G groups to add to)
usermod -a -G untrusted untrusted
# Create "trusted_group"
sudo groupadd trusted_group
# Add every user on system other then "untrusted" to the "trusted_group"
# Cut passwd down to first column (usernames) (seperated by ';'), remove "untrusted" username, add each to "trusted_group"
cat /etc/passwd|cut -f 1 -d ':'|grep -v untrusted|xargs -n1 -I'{}' bash -c "sudo usermod -a -G trusted_group {}"


#######################################
## Create directories for our system ##
#######################################

# Root
sudo mkdir -p /sip

# Executables
sudo mkdir -p /sip/executables

# Logs
sudo mkdir -p /sip/logs
sudo chown $realUserName /sip/logs
chmod u+rx /sip/logs

# Daemon communication path
mkdir -p ~/sip_daemon
sudo chown $realUserName ~/sip_daemon
chmod a+rx ~/sip_daemon


#################################
## Generate common header file ##
#################################
./configure.sh


#####################################
## Install glibc wrapper libraries ##
#####################################
../library/install.sh


# TODO: build uudo executable with make and add to path (see 98-99, 106 in lwip_installation/install.sh)
# TODO: determine if/where PiP changes the permissions on world-executables/world-writables

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