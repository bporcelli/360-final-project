# Overview

System Integrity Protection (SIP) is a simple mechanism for protecting system integrity while executing untrusted programs.
It was developed in collaboration with [@colinmonteil](https://github.com/colinmonteil) and [@saltermine](https://github.com/saltermine)
as a final project for our [Software Security course](https://www.cs.stonybrook.edu/students/Undergraduate-Studies/courses/CSE360).

This is an experimental system developed for a course project. It **should NOT be used to protect real-world systems.**

# Architecture

SIP implements a simplified version of the dual-sandboxing architecture described by Wai-Kit Sze and R.Sekar in 
[A Portable User-Level Approach for System-wide Integrity Protection](http://seclab.cs.sunysb.edu/seclab/pubs/acsac13.pdf).
A full description of the system architecture can be found [here]().

# Compatibility

System Integrity Protection (SIP) has been tested (albeit in a limited fashion) on Ubuntu LTS 16.04.

# Usage

To use SIP, simply...

1. `git clone https://github.com/bporcelli/system-integrity-protection/`
2. `cd system-integrity-protection`
3. `sudo install.sh`
4. Use the `runt` command to execute untrusted programs, e.g. `runt rm -rf *`
