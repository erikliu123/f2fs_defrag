obj-$(CONFIG_F2FS_FS) += f2fs.o
f2fs-y := dir.o file.o inode.o namei.o hash.o super.o inline.o
f2fs-y += checkpoint.o gc.o data.o node.o segment.o recovery.o
f2fs-y += shrinker.o extent_cache.o sysfs.o
f2fs-$(CONFIG_F2FS_STAT_FS) += debug.o
f2fs-$(CONFIG_F2FS_FS_XATTR) += xattr.o
f2fs-$(CONFIG_F2FS_FS_POSIX_ACL) += acl.o
f2fs-$(CONFIG_F2FS_IO_TRACE) += trace.o

KERNELDIR:=/usr/src/linux-headers-4.15.0-29deepin-generic
#PWD:=`cd $(dirname $0); pwd -P`
PWD:=`pwd`

default:
	make -C $(KERNELDIR) M=$(PWD) modules
clean:
	rm -rf *.o *.mod.c *.ko *.symvers


