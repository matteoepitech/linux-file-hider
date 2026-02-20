##
## DEL PROJECT, 2026
## Makefile
## File description:
## LINUX FILE HIDER KERNEL MODULE MAKEFILE
##

obj-m += lfh.o

KERNEL_VERSION	:=	$(shell uname -r)
KERNEL_DIR	:=	/lib/modules/$(KERNEL_VERSION)/build

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

load:
	sudo insmod lfh.ko

unload:
	sudo rmmod lfh

logs:
	sudo dmesg -w
