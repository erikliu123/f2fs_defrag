#sudo
echo 1 >  /sys/kernel/debug/tracing/tracing_on
echo 1 >  /sys/kernel/debug/tracing/events/f2fs/enable 
set var="sda8"
#make clean
make
umount /dev/$var
rmmod f2fs
insmod f2fs.ko

mkfs.f2fs -l f2fs -f /dev/sda9
mount -t f2fs -o active_logs=6 /dev/sda9 /mnt/test

