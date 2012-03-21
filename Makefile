obj-m		:= ip_carp.o
ip_carp-objs	:= carp.o carp_log.o carp_queue.o

KDIR	:= /usr/src/linux-headers-$(shell uname -r)
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	gcc -W -Wall carpctl.c -o carpctl

copy:
	scp ip_carp.ko carpctl mtest:carp/
	scp ip_carp.ko carpctl pcix:aWork/carp/

clean:
	rm -f *.o *.ko *.mod.* .*.cmd *~ carpctl
	rm -rf .tmp_versions modules.order  Module.symvers
