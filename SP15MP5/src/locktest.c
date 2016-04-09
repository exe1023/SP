#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
int main(void)
{
	char *path = (char*)malloc(500);
	strcpy(path , "/nfs/undergrad/03/b03902071/SP/MP4/file");
	int fd = open(path , O_WRONLY);
	printf("file %d open\n" , fd);
	struct flock setlk;
	setlk.l_type = F_WRLCK; 
	setlk.l_whence = SEEK_SET;
	setlk.l_start = 0;
	setlk.l_len = 0;
	setlk.l_pid = 0;
	struct flock getlk;
	getlk.l_type = F_WRLCK;
	getlk.l_whence = SEEK_SET;
	getlk.l_start = 0;
	getlk.l_len = 0 ;
	getlk.l_pid = 0;
	if(fcntl(fd , F_SETLK , &setlk) < 0)
		printf("lock error\n");
	if(fcntl(fd , F_GETLK , &setlk) < 0)
		printf("getlock error\n");
	printf("%d %d\n" , F_WRLCK , F_UNLCK);
	printf("pid = %d , locktype = %d\n" , setlk.l_pid , setlk.l_type);
	printf("start sleep\n");
	sleep(15);
}
