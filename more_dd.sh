cd /mnt/fs
count=1
until [  "$count" == "1000" ] #400000 * 4K    25000
do
	rand=$RANDOM
	let "rand %= 20" #50
	let "rand += 40"
	dd if=/dev/zero of="multi-${rand}" bs=4K count=1 oflag=append conv=notrunc oflag=sync > /dev/null 2>&1
	let "count += 1"
	
done

