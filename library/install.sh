#!/bin/bash

######################################
## Installs glibc wrapper libraries ##
######################################


#############################################
## NOTE: MUST BE RUN WITH ROOT PERMISSIONS ##
#############################################

CWD=$(dirname $0)
cd $CWD

##############################
## Compile shared libraries ##
##############################
make clean lib

####################################################
## Copy our glibc wrapper libraries into usr/lib/ ##
####################################################
LIB_DIR="/usr/lib/"
LIBS=("libsipwrap.so")
cp -t $LIB_DIR ${LIBS[@]/#/bin/}

##############################################################
## Append the name of our '.so' file to 'etc/ld.so.preload' ##
##############################################################
# Enter the names of overriding libraries (.o files) in /etc/ld.so.preload
# These "preloading" libraries will take precedence over the standard set.
# It contains names of libraries to be loaded, separated by white spaces or `:'.
libs_appended=0
for lib in $LIBS
do
	if [[ $libs_appended == 0 ]]; then
		# Overwrites the file
	  	echo "$lib" > "/etc/ld.so.preload"
	else
		# Appends to the file
		echo ":$lib" >> "/etc/ld.so.preload"
	fi
	let libs_appended++
done

#####################################################################
## Call ldconfig(8) to update the cache used by the program loader ##
#####################################################################
ldconfig