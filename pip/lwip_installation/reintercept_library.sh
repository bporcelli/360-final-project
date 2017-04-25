#!/bin/bash

distribution=`lsb_release -i |gawk '{print $3}'`
distribution_release=`lsb_release -r |gawk '{print $2}'`

declare -A supported_systems
for supported_system in "Ubuntu_10.04" "Ubuntu_10.10" "Ubuntu_11.04"
do
	supported_systems[$supported_system]=1
done

current_system="$distribution"_"$distribution_release"

if [[ ${supported_systems["$distribution"_"$distribution_release"]} -ne 1 ]]; then 
	echo "[Error] Your distribution is unsupported:" "$distribution"_"$distribution_release"
	exit 1
fi



if [[ "$current_system" == "Ubuntu_10.04" ]]; then
	libs2intercept=( "/lib/libc.so.6" "/lib/libpthread.so.0" "/lib/tls/i686/cmov/libpthread.so.0" "/lib/tls/i686/cmov/libc.so.6" )
elif [[ "$current_system" == "Ubuntu_10.10" ]]; then
	libs2intercept=( "/lib/libc.so.6" "/lib/libpthread.so.0" )
elif [[ "$current_system" == "Ubuntu_11.04" ]]; then
	libs2intercept=( "/lib/i386-linux-gnu/libc.so.6" "/lib/i386-linux-gnu/libpthread.so.0" )
else
	echo "[Error] Unknown path for libc and libpthread!!"
	exit 1
fi

library_backup_dir=/lwip/library/backup
intercepted_dir=/lwip/library/intercepted

#This part is about intercepting the required libraries
for lib in ${libs2intercept[*]}
do
        libPath=$(readlink -f $lib)
        dirPath=$(dirname $libPath)
        basename=$(basename $libPath)
        mkdir -p $library_backup_dir$dirPath
        cp $libPath $library_backup_dir$dirPath
        ln -sf $basename $library_backup_dir$lib

        mkdir -p $intercepted_dir$dirPath

	echo -ne "Intercepting $libPath, outputing at $intercepted_dir$libPath.intercepted ... "
	./library_interceptor/intercept.sh $libPath $intercepted_dir$libPath.intercepted > /dev/null
	echo "Done"

        ln -sf $basename.intercepted $intercepted_dir$lib
done

sudo cp -vL /lwip/library/intercepted/lib/* /lib
