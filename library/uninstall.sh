#!/bin/bash

CWD=$(dirname $0)
cd $CWD

#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

###############################
## Reset 'etc/ld.so.preload' ##
###############################
> "/etc/ld.so.preload"

##############################
## Compile shared libraries ##
##############################
make lib

######################################################
## Remove our glibc wrapper libraries from usr/lib/ ##
######################################################
lib_dir="/usr/lib"
libs=$(find bin/ -name *.so)
for lib in $libs
do
	lib=${lib#bin/}
	rm -f "$lib_dir/$lib"
done

#####################################################################
## Call ldconfig(8) to update the cache used by the program loader ##
#####################################################################
ldconfig

###############################
## Clean up shared libraries ##
###############################
make clean all