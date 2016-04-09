#include <stdio.h>
#include <stdlib.h>

int main(int argc , char **argv)
{
	char *string = (char *)malloc(sizeof(char) * 100000010);
	FILE *fp1 = fopen(argv[1] , "r");
	FILE *fp2 = fopen(argv[2] , "r");
	FILE *fp3 = fopen(argv[3] , "w");
	if(fp1 == NULL)
		printf("error1\n");
	if(fp2 == NULL)
		printf("error2\n");
	if(fp3 == NULL)
		printf("error3\n");
	//printf("%s , %s , %s" , argv[1] , argv[2] , argv[3]);
	for(int i = 0 ;  i < 1 ; i++)
	{
		fgets(string , 100000010 , fp1);
		//fseek(fp1 , 100000010 , SEEK_SET);
		fseek(fp1 , 0 , SEEK_SET);
		//fprintf(fp3 ,"%s" , string);
		fgets(string , 100000010 , fp2);
		//fseek(fp2 , 100000010 , SEEK_SET);
		fseek(fp2 , 0 , SEEK_SET);
	}
}