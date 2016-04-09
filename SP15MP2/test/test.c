#include <stdio.h>
#include "hash.h"

int main(void)
{
	struct hash test;
	init_hash(&test , 300);
	char a[10] = "abc";
	char b[10] = "def";
	char c[10] = "ghk";
	put_into_hash(&test , (void *)a , 1);
	put_into_hash(&test , (void *)b , 2);
	put_into_hash(&test , (void *)c , 3);

	char *temp;
	get_from_hash(&test , &temp , 1);
	printf("%s" ,temp);
}