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
	struct flock getlk;
	getlk.l_type = F_RDLCK;
	getlk.l_whence = SEEK_SET;
	getlk.l_start = 0;
	getlk.l_len = 0 ;
	getlk.l_pid = 0;
	if(fcntl(fd , F_GETLK , &getlk) < 0)
		printf("getlock error\n");
	//if(getlk.l_type != F_UNLCK)
		printf("lock pid = %d locktype = %d\n" , getlk.l_pid , getlk.l_type);
	//sleep(15);
}
