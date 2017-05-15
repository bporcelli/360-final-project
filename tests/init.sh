#! /bin/bash

FD=files

# Remove files
rm -f files/*.txt

# Create files
cp -f files/template files/benign-file.txt
cp -f files/template files/benign-file-no-downgrade.txt
cp -f files/template files/untrusted-file.txt

# Set ownership
chown sekar:sekar files/benign-file.txt
chown sekar:trusted_group files/benign-file-no-downgrade.txt
chown sekar:untrusted files/untrusted-file.txt

# Set perms
chmod u+rw,o-rwx,g-rwx files/benign-file.txt # Force delegation when opened for reading