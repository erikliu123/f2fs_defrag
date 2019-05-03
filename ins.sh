#sudo 
#/home/peter/linux-4.15/fs/f2fs
#make clean
#echo -n "Enter your choice:"   #参数-n的作用是不换行，echo默认是换行
if [ $# -ne 2 ]; then
	echo "输入选项 [intsall | remove] [设备]"
	exit
fi
echo "the shell is for HDD"
if [ "$1" == "mount" ]; then
	mount -t f2fs -o active_logs=2 $2 /mnt/hdd
elif [ "$1" == "remove" ]; then
	umount /dev/sda9
	rmmod f2fs
	if [ "$?　-eq 0" ]; then
		echo "remove success"
		exit -1
	else
		echo "remove in failure"
		exit
	fi
	
elif [ "$1" == "install" ]; then
	make
	rmmod f2fs
	insmod f2fs.ko
#mkfs.f2fs -l f2fs -f /dev/sda8
#mount -t f2fs -o active_logs=6 /dev/sda8 /mnt/f2fs
	if [ "$? -eq 1" ]; then
		mount -t f2fs -o active_logs=2 $2 /mnt/hdd
		echo "insmod successful!"
	else
		mount -t f2fs -o active_logs=2 $2 /mnt/hdd
	fi
else 
	echo "unrecognized input!"
#elif [ "$name" == "extract" ]; then
fi
