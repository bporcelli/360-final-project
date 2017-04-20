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


