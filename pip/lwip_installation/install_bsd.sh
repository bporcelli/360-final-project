#!/bin/bash

sudo pw useradd -nuntrusted -u1004
#sudo pw usermod ubuntu -G untrusted
sudo pw useradd -u1005 -nuntrustedRoot 

sudo pw groupadd -g1006 -ntrusted_group
cat /etc/passwd|grep ":"|cut -f 1 -d ':'|grep -v untrusted|xargs -n1 -I'{}' bash -c "sudo pw usermod {} -G trusted_group"
