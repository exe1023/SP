#include <stdio.h>

int main(int argc , char *argv[])
{
	FILE *fp1 , *fp2;
	fp1 = fopen(argv[1] , "r");
	fp2 = fopen(argv[2] , "w");
	int count = 0;
	char alphabet , table[10] = {'a','e','i','o','u','A','E','I','O','U'};
	while(fscanf(fp1 , "%c",&alphabet) != EOF)
	{
		for(int i = 0 ; i < 10 ; i++)
			if(alphabet == table[i])
			{
				count ++;
				break;
			}
	}
	fprintf(fp2 ,"%d" , count);
}