cd /mnt/fs
count=0
echo 2000 > /sys/kernel/debug/tracing/buffer_size_kb
echo "" > /sys/kernel/debug/tracing/trace
echo 1 >  /sys/kernel/debug/tracing/tracing_on
#echo 1 >  /sys/kernel/debug/tracing/events/block/enable
echo 1 >  /sys/kernel/debug/tracing/events/f2fs/enable
until [  "$count" == "400000" ] #400000 * 4K
do
	rand=$RANDOM
	let "rand %= 20" #50
	dd if=/dev/zero of="multi-${rand}" bs=4K count=1 oflag=append conv=notrunc oflag=sync > /dev/null 2>&1
	let "count += 1"
	
done

#exit 0
echo 0 >  /sys/kernel/debug/tracing/tracing_on
exit 0


