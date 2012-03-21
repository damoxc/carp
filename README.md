This is an implementation of CARP for the Linux kernel. It's currently very
rough and based off of the code found from the netdev mailing list circa
2004. It's been forward-ported to work (partially) on modern kernels.

A rough plan is:

 - Add sysfs and procfs interfaces
 - Dynamic adding of carp interfaces
