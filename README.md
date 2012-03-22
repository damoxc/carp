This is an implementation of CARP for the Linux kernel. It's currently very
rough and based off of the code found from the netdev mailing list circa
2004. It's been forward-ported to work (partially) on modern kernels.

A rough plan is:

 - Add sysfs and procfs interfaces
 - Ensure everything is async

Known Issues
 - Doesn't actually allow network traffic through yet
 - carp devices can use the same vhid
 - Causes kernel oops if eth0 isn't configured but does exist
