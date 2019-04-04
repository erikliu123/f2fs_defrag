#1）清理pagecache（页面缓存）
echo 1 > /proc/sys/vm/drop_caches     或者 # sysctl -w vm.drop_caches=1
 
#2）清理dentries（目录缓存）和inodes
echo 2 > /proc/sys/vm/drop_caches     或者 # sysctl -w vm.drop_caches=2
 
#3）清理pagecache、dentries和inodes
echo 3 > /proc/sys/vm/drop_caches   

sleep 10  
