
if [ $# -ne 2 ]; then
	echo -e "输入挂载的目录和dd选项\n [/mnt/?] [0=continuous, 1=scatter]\n"
	exit
fi
cd $1
filenum=2  #文件数目
#bs=8K filechunk=8M/bs
filechunk=2048 #2048*4KB=8MB 32*256 1024*8K
count=0
rand=0
#BS size会随filechunk改变
bssize=`expr 8192 / $filechunk`
if [ "$2" == "1" ]; then
until [  $count -eq `expr $filechunk \* $filenum` ] #400000 * 4K    25000
do
	#rand=$RANDOM
	let "rand %= $filenum" # 
	let "rand += 91" #+? 需要调整
	#echo $rand
	dd if=/dev/zero of="tmp${rand}.txt" bs=${bssize}K count=1 oflag=append conv=notrunc oflag=sync > /dev/null 2>&1
	#let "rand += 1"
	let "count += 1"
	
done
#fi
elif  [ "$2" == "0" ]; then
until [  $count -eq $filechunk ] #400000 * 4K    25000
do
	#rand=$RANDOM
	#let "rand = 0" #50
	
	#echo $rand
	dd if=/dev/zero of="file${rand}.txt" bs=4K count=1 oflag=append conv=notrunc oflag=sync > /dev/null 2>&1
	
	let "count += 1"
	
done

else
	echo "unrecognized input!"
fi

