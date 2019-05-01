#年月日时
#mount -t f2fs -o active_logs=6 /dev/sda9 /mnt/fs
output_file=` date "+%Y-%m-%d_%H.txt"`

last_kedu="0.000000"
count=0
hasnew=1
pwd=`pwd`
cd trace
#echo "" > /sys/kernel/debug/tracing/trace
#USE SUDO!!
echo 1 >  /sys/kernel/debug/tracing/tracing_on
#echo 1 >  /sys/kernel/debug/tracing/events/block/enable
echo 1 >  /sys/kernel/debug/tracing/events/f2fs/enable

#echo "remove f2fs.ko"
#$pwd"/./ins.sh" remove

#exit
echo  $#
if [ $# -ne 1 ]; then #好像服务器的then前面可以不需要分号？
	echo "输入计数次数..."
	exit
fi
if [ -f $output_file ]; then #-f是文件 -d是目录
	last_kedu=`cat $output_file | grep "free" | tail -1 | sed  -n 's/.*\[\s*\(.*\)].*/\1/p'`
	echo "最后的时间刻度=$last_kedu"

fi

until [  $count -eq $1 ]
do
	dmesg > dmesg.txt
	cat dmesg.txt | egrep -n 'free|gc_type' | tail -2  > dmesg2.txt
	
	before=`cat dmesg2.txt |sed -n '1p'`
	after=`cat dmesg2.txt |sed -n '2p'`

	echo $before | grep 'gc_type' #找到返回0
	if [ $? -eq 1 ]; then #没找到,是free，说明现在正在GC操作
		sleep 20
		continue;
	fi
	echo $after | grep 'gc_type' #连续两次都是GC,说明上次的GC无效
	if [ $? -eq 0 ]; then #没找到,是free，说明现在正在GC操作
		sleep 20
		continue	
	fi

	current=`echo $after | sed -n 's/.*\[\s*\(.*\)].*/\1/p'` #得到时间,还是上次的GC结果
	echo "[current]="$current
	if [ "$current" == "$last_kedu" ]; then
		sleep 10
		continue
	fi
	#dmesg | sed -n '/free/p' | while read line
	#do
	#temp=`echo $line | sed -n 's/\[\(.*\)\].*/\1/p'`  #得到free的时间
	#echo $temp
	begin_line=`echo $before | sed -n 's/\(\d*\):.*/\1/p'`
	end_line=`echo $after | sed -n 's/\(\d*\):.*/\1/p'`
	out=$begin_line","$end_line"p"
	sed -n "$out" dmesg.txt >> $output_file #sed 必须用双引号
	#done
	let "count+=1"
	echo "已经写入次数$count..."
	last_kedu=$current
	if [ $count -eq $1 ]; then 
		echo "GC 记录结束,调用ins.sh移走模块f2fs..."
		$pwd"/./ins.sh" remove
		exit	
		
	fi 
	sleep 20

done
