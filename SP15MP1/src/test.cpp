#include <stdio.h>
#include <stdlib.h>
int main(int argc, char** argv)
{
	FILE *fp1 = fopen(argv[1] , "w"), *fp2 = fopen(argv[2] , "w");

	for(int i = 0 ; i < 0 ; i ++)
	{
		for(int j = 0 ; j < 100000000 ; j ++)
			fprintf(fp1 , "1");
		fprintf(fp1 , "\n");
	}
	for(int i = 0 ; i < 100000000 ; i ++)
		fprintf(fp1 , "2");
	fprintf(fp1 , "\n");
	for(int i = 0 ; i< 0 ; i++)
	{
		for(int j = 0 ; j < 100000000 ; j++)
			fprintf(fp1 , "1");
		fprintf(fp1 , "\n");
	}
	for(int i = 0 ; i < 1 ; i++)
	{
		for(int j = 0 ; j < 100000000 ; j ++)
			fprintf(fp2 , "1");
		fprintf(fp2 , "\n");
	}
}