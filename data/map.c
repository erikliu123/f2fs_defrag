#include<stdio.h>
#include<linux/fs.h>
#include<unistd.h>

int fd;
int main(int argc, char **argv){
	
	if(argc<3){
		printf("参数过少\n");
		return 0;	
	}
	fd=open(argv[1],0);//"/mnt/fs/ics2018"
	printf("fd=%d\n",fd);
	char buf[8];
	int ranges;
	
	ranges=atoi(argv[2]);
	printf("rangs=%d\n",ranges);
	int res=ioctl(fd,0xf8f9,&ranges);
	printf("res=%d\n",res);

	return 0;	
}

