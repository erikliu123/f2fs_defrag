#include<stdio.h>
#include<linux/fs.h>
#include<unistd.h>

int fd;
int main(int argc, char **argv){
	
	if(argc<4){
		printf("参数过少,需要[文件] [起始偏移块（4K）] [结束偏移块（4K）]\n");
		return 0;	
	}
	fd=open(argv[1],0);//"/mnt/fs/ics2018"
	printf("fd=%d\n",fd);
	char buf[8];
	int ranges[2];
	
	ranges[0]=atoi(argv[2]);
	ranges[1]=atoi(argv[3]);
	printf("ranges[0]=%d\n",ranges[0]);
	int res=ioctl(fd,0xf8f8,ranges);
	printf("res=%d\n",res);

	return 0;	
}

