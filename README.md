360-final-project

Brett Porcelli:
Colin Monteil-anatra:
Salvatore Termine: 109528463

We will implement a simplified dual-sandboxing architecture based on PIP.
Similar to PIP, we will exploit OS access controls to enforce sandboxing 
of untrusted programs: Untrusted programs will be run with a userid that 
has limited-to-no access to the filesystem. Untrusted processes will be 
forced to access files through a trusted helper process, which will 
redirect or restrict requests as needed to protect the integrity of the 
system. The inner sandbox (based on OS access controls) will be as 
described in section 2.1 of the PIP paper; however, we should explore 
possible simplifications, e.g. using one untrusted userid, or creating 
an untrusted userid for each application instead of each existing user.
The transparency library (UL) and benign library (BL) will be implemented 
using user-level system call interposition as described in sections 2.2 to 
3.2 of the paper, with some exceptions: All attempts by untrusted programs 
to write to benign files will be blocked, not just those targeted at code, 
configuration or preference files (similar to one-way isolation). 
Unfortunately we will still have a lot of filesystem fragmentation, but we 
avoid the complexity of distinguishing code, configuration, and preference 
files from input files.

Benign programs will always be run in "isolation mode." We can attempt to 
support limited interaction between untrusted and trusted programs if we 
have time to spare after the basic implementation is complete. Users will 
be required to invoke untrusted executables using a command line utility 
like uudo (described in section 3.1). Again, we can attempt to support 
automatic invocation of untrusted programs with uudo if time allows.

IF we can accomplish all of the above, we can try to implement support 
for commit operations. This would eliminate at least some of the 
inconvenience caused by filesystem fragmentation. To avoid dealing with 
consistency criteria described at length in the Alcatraz paper, I suggest 
that we force the admin to enable mandatory file locks.
