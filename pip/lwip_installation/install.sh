#!/bin/bash

# Get current OS information
distribution=`lsb_release -i |gawk '{print $3}'`
distribution_release=`lsb_release -r |gawk '{print $2}'`
current_system="$distribution"_"$distribution_release"
# Find out if OS is supported
declare -A supported_systems
for supported_system in "Ubuntu_10.04" "Ubuntu_10.10" "Ubuntu_11.04"
do
	supported_systems[$supported_system]=1
done
if [[ ${supported_systems["$distribution"_"$distribution_release"]} -ne 1 ]]; then 
	echo "[Error] Your distribution is unsupported:" "$distribution"_"$distribution_release"
	exit 1
fi


# Get list of libraries to intercept based on version
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


echo -ne "Creating directory for the system at /lwip ... "
sudo mkdir -pv /lwip
echo "Done"

# Create directories for library backups and intercepted libraries
library_backup_dir=/lwip/library/backup
intercepted_dir=/lwip/library/intercepted
echo "Creating library backup directory at $library_backup_dir ... "
echo "Creating intercepted library directory at $intercepted_dir ... "
mkdir -pv $library_backup_dir
mkdir -pv $intercepted_dir

#This part is about intercepting the required libraries
for lib in ${libs2intercept[*]}
do
        # Get path to lib (Follow symlinks to end)
        libPath=$(readlink -f $lib)
        # Get parent dir of this lib
        dirPath=$(dirname $libPath)
        # Get lib name
        basename=$(basename $libPath)
        # Make dir for this lib in backup
        mkdir -p $library_backup_dir$dirPath
        # Copy lib to backup dir
        cp $libPath $library_backup_dir$dirPath
        # Create symlink for lib name in backup_dir/lib_path
        ln -sf $basename $library_backup_dir$lib
        # Make dir for this lib in intercepted
        mkdir -p $intercepted_dir$dirPath

    # Run intercept.sh with the args of  lib_name and /intercepted_dir/lib_name.intercetped
	echo -ne "Intercepting $libPath, outputing at $intercepted_dir$libPath.intercepted ... "
	./library_interceptor/intercept.sh $libPath $intercepted_dir$libPath.intercepted > /dev/null
	echo "Done"

		# Create symlink for lib_name.intercepted in intercepted_dir.lib_path 
        ln -sf $basename.intercepted $intercepted_dir$lib
done


realUserName=`whoami`
if [[ $realUserName == "root" ]]; then
  realUserName=$SUDO_USER
fi


useradd -u 1004 untrusted
usermod -a -G untrusted $realUserName
useradd -u 1005 untrustedRoot

sudo groupadd trusted_group
cat /etc/passwd|cut -f 1 -d ':'|grep -v untrusted|xargs -n1 -I'{}' bash -c "sudo usermod -a -G trusted_group {}"

sudo apt-get install -y libnotify-bin libcap-dev pcregrep libsqlite3-dev m4 xserver-xephyr


sudo touch /bin/restoreLib
sudo chmod +x /bin/restoreLib

sudo touch /bin/replaceLib
sudo chmod +x /bin/replaceLib

#./lwip_installer/configure.sh


#This part copies the required binaries
sudo mkdir /lwip/executables

./../lwip_new/install.sh

#sudo cp -Lvr executables /lwip
sudo cp re*Lib /lwip/executables/

#sudo chown root:root /lwip/executables/*
#sudo chown $realUserName:$realUserName /lwip/executables/redirectHelper


#sudo chmod +s /lwip/executables/*

sudo rm /bin/restoreLib /bin/replaceLib

sudo ln -sf /lwip/executables/uudo /bin/uudo
sudo ln -sf /lwip/executables/restoreLib /bin
sudo ln -sf /lwip/executables/replaceLib /bin
sudo ln -sf /lwip/executables/redirectHelper /bin


ln -s /lwip/executables/re*Lib ~


#Secure installer

#sudo mkdir -p /redirection/union_root
#sudo mkdir -p /redirection/redirected_root

#sudo mkdir /usr/bin/wrapper
#sudo cp /usr/bin/dpkg /usr/bin/wrapper/

#sudo sh secure_installer/install.sh

#This part is about replacing the libraries
sudo cp -vL libraries/* /lib

for lib in ${libs2intercept[*]}     
do 
        libPath=$(readlink -f $lib)   
        dirPath=$(dirname $libPath)          
        basename=$(basename $libPath)
	linkname=$(basename $lib)

	sudo cp -v $intercepted_dir$libPath.intercepted $dirPath
	sudo ln -sfv $basename.intercepted $dirPath/$linkname

done

mkdir ~/lwip_communication
sudo chown $realUserName ~/lwip_communication
lwip_trusted chmod a+rx ~/lwip_communication


sudo chmod a+rw ~/Desktop/*

sudo mv /usr/lib/openoffice/program/soffice /usr/lib/openoffice/program/soffice.bak
sudo ln -s soffice.bin /usr/lib/openoffice/program/soffice


cp -v update_lwip.sh ~/



cd /usr/bin
sudo mv evince evince.bin
sudo ln -s evince.bin evince


sudo mkdir -p /lwip/opendb
sudo chgrp trusted_group /lwip/opendb
sudo chmod ug+rwx,o=rx /lwip/opendb




#sudo reboot
