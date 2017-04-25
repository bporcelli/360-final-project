#!/bin/bash

CWD=$(readlink -f $0)
CWD=$(dirname $CWD)
cd $CWD

cd ~/lwip/lwip_new
message=$(git pull origin master 2>&1)

echo $message

updated=$(echo "$message"|grep "Already up-to-date")
conflict=$(echo "$message"|grep "Aborting")


if [ ! -z "$conflict" ]; then
        echo "Conflict in commit!!!"
        echo "Check with command: \"git pull seclab-wsze master\""
        echo "Issue git checkout -- . to discard the changes" 
        exit -1;
fi
if [ -z "$updated" ]; then
        make clean
        sudo make install
else
        echo "No new update"
fi


