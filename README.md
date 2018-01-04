# Overview

System Integrity Protection (SIP) is a simple mechanism for protecting system integrity while executing untrusted programs.
It was developed in collaboration with [@colinmonteil](https://github.com/colinmonteil) and [@saltermine](https://github.com/saltermine)
as a final project for our [Software Security course](https://www.cs.stonybrook.edu/students/Undergraduate-Studies/courses/CSE360).

**SIP should NOT be used to protect real-world systems.**

# Architecture

SIP implements a simplified version of the dual-sandboxing architecture described by Wai-Kit Sze and R.Sekar in 
[A Portable User-Level Approach for System-wide Integrity Protection](http://seclab.cs.sunysb.edu/seclab/pubs/acsac13.pdf).
A description of the differences between our system and the one proposed by Sze and Sekar can be found [here](https://drive.google.com/open?id=1zYkeloFTlidUJXZYHvP9ldyRtPeMAJyi).

# Compatibility

System Integrity Protection (SIP) has been tested (albeit in a limited fashion) on Ubuntu LTS 16.04.

# Installation

To use SIP, simply...

1. `git clone https://github.com/bporcelli/system-integrity-protection/`
2. `cd system-integrity-protection/install`
3. `sudo install.sh`

# Usage

After installing SIP, you can use the `runt` command to execute untrusted programs, e.g. `runt rm -rf *`.

# Uninstallation

To uninstall SIP, cd into the `install` directory and run the command `sudo uninstall.sh`.
