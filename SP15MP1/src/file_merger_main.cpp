#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <stack>
#define maxstring 100000010
#define maxtable 10050000

using namespace std;
typedef struct member
{
	short direct; // 0 means leftup , 1 means left , 2 means up
	int prefix_len;
}Member;
int count_line(FILE *fp)
{
	int count = 0;
	char c = getc(fp);
	while(c != EOF)
	{
		if(c == '\n')
			count ++;
		c = getc(fp);
	}
	count++ ;// add the dummy line
	return count;
}

int build_LCStable(FILE *fp1 , FILE *fp2 , Member *table , int line1 , int line2)
{
	int table_count = 0;
	char *string1 = (char *)malloc(sizeof(char) * maxstring);
	char *string2 = (char *)malloc(sizeof(char) * maxstring);
	char ans[100];
	for(int i = 0 ; i < line1 ; i++)
	{
		if(i > 0)
			fgets(string1 , maxstring , fp1);
		else
			string1[0] = '\0';

		for(int j = 0 ; j < line2 ; j++ , table_count++)
		{
			if(j > 0)
				fgets(string2 , maxstring , fp2);
			else
				string2[0] = '\0';
			if((i == 0 && j == 0) || strcmp(string1 , string2) == 0)
			{
				table[table_count].direct = 0;
				if(i == 0 || j == 0)
					table[table_count].prefix_len = 0;
				else
				{
					table[table_count].prefix_len = table[table_count - line2 - 1].prefix_len + 1;
				}
			}
			else
			{
				if(i == 0)
				{
					table[table_count].direct = 1;
					table[table_count].prefix_len = 0;
				}
				else if(j == 0)
				{
					table[table_count].direct = 2;
					table[table_count].prefix_len = 0;
				}
				else
				{
					if(table[table_count - line2].prefix_len > table[table_count - 1].prefix_len)
					{
						table[table_count].direct = 2;
						table[table_count].prefix_len = table[table_count - line2].prefix_len;
					}
					else
					{
						table[table_count].direct = 1;
						table[table_count].prefix_len = table[table_count - 1].prefix_len;
					}
				}
			}
		}

		fseek(fp2 , 0 , SEEK_SET);
	}
	return table_count;
}

void build_path(Member *table , int table_count, int line1 , int line2 , stack<int> &path)
{
	table_count --;
	int last_direct = 0 ;
	while(table_count > 0)
	{
		if(table[table_count].direct == 0)
		{
			if( last_direct != 0 && table[table_count - (line2 + 1)].direct != 0 && table_count - (line2 + 1) > 0)
			{
				path.push(3); // the collision which should be ignored
				last_direct = 3;
			}
			else
			{
				path.push(0);
				last_direct = 0;
			}
			table_count -= (line2 + 1);
		}
		else if(table[table_count].direct == 1)
		{
			path.push(1);
			last_direct = 1;
			table_count -= 1;
		}
		else
		{
			path.push(2);
			last_direct = 2;
			table_count -= line2;
		}
	}
}

void print_collision(FILE *fp1 , FILE *fp2 , FILE *fp3 ,int &start1 , int &end1 , int &start2 , int &end2 , char *file1 , char *file2)
{
	if(start1 == -1 && start2 == -1)
		return;
	char *string = (char *)malloc(sizeof(char) * maxstring);
	fprintf(fp3 , ">>>>>>>>>> %s\n" , file1);

	if(start1 >= 0)
	{
		fseek(fp1 , start1 , SEEK_SET);
		while(ftell(fp1) != end1)
		{
			fgets(string , maxstring , fp1);
			fprintf(fp3 , "%s", string);
		}
	}
	fprintf(fp3 , "========== %s\n" , file2);
	if(start2 >= 0)
	{
		fseek(fp2 , start2 , SEEK_SET);
		while(ftell(fp2) != end2)
		{
			fgets(string , maxstring , fp2);
			fprintf(fp3 , "%s" , string);
		}
	}
	fprintf(fp3 , "<<<<<<<<<<\n");
	free(string);
}

void traverse_and_print(stack<int> path , FILE *fp1 , FILE *fp2 , FILE *fp3 , char *file1 , char *file2)
{
	char *string1 = (char *)malloc(sizeof(char) * maxstring);
	char *string2 = (char *)malloc(sizeof(char) * maxstring);
	int start1 = -1, start2 = -1, end1 = -1, end2 = -1;
	while(!path.empty())
	{
		//printf("%d\n" , path.top());
		if(path.top() == 0)
		{
			end1 = ftell(fp1);
			end2 = ftell(fp2);
			print_collision(fp1 , fp2 , fp3 , start1 , end1 , start2 , end2 , file1 , file2);
			start1 = -1; start2 = -1; end1 = -1; end2 = -1;

			fgets(string1 , maxstring , fp1); fgets(string2 , maxstring , fp2);
			fprintf(fp3 , "%s" , string1);
		}
		else if(path.top() == 1)
		{
			if(start2 == -1)
				start2 = ftell(fp2);
			fgets(string2 , maxstring , fp2);
		}
		else if(path.top() == 2)
		{
			if(start1 == -1)
				start1 = ftell(fp1);
			fgets(string1 , maxstring , fp1);
		}
		else if(path.top() == 3)
		{
			if(start1 == -1)
				start1 = ftell(fp1);
			if(start2 == -1)
				start2 = ftell(fp2);
			fgets(string1 , maxstring , fp1);
			fgets(string2 , maxstring , fp2);
		}
		path.pop();
	}
	end1 = ftell(fp1);
	end2 = ftell(fp2);
	print_collision(fp1 , fp2 , fp3 , start1 , end1 , start2 , end2 , file1 , file2);

}

int main(int argc, char** argv) {
  Member *table = (Member *)malloc(sizeof(Member) * maxtable);
  for(int i = 0 ; i < maxtable ; i ++)
  {
  	table[i].direct = -2;
  	table[i].prefix_len = -2;
  }
  FILE *fp1 , *fp2;
  char *file1 , *file2;
  fp1 = fopen(argv[1] , "r");
  fp2 = fopen(argv[2] , "r");
  file1 = basename(argv[1]);
  file2 = basename(argv[2]);

  int line1 = count_line(fp1), line2 = count_line(fp2);
  fseek(fp1 , 0 , SEEK_SET); fseek(fp2 , 0 , SEEK_SET);

  int table_count = build_LCStable(fp1 , fp2 , table , line1 , line2);
  int count = 0;
  for(int i = 0 ; i < line1 ; i++)
  {
  	for(int j = 0 ; j < line2 ; j++ , count++)
  		printf("%d " , table[count].prefix_len);
  	printf("\n");
  }
  stack<int> path;
  build_path(table ,table_count , line1 , line2 , path);
  fseek(fp1 , 0 , SEEK_SET); fseek(fp2 , 0 , SEEK_SET);
  FILE *fp3 = fopen(argv[3] , "w");
  traverse_and_print(path , fp1 , fp2 , fp3 , file1 , file2);
  return 0;
}