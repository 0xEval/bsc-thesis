#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* safe_string = "/bin/sh";

void tchoo_tchoo(char* buffer)
{	
	printf("Here comes the train \n:");
	system("/bin/sl");
}

void vuln_func(char* string)
{
	char buffer[100];
	strcpy(buffer, string);
}

int main(int argc, char** argv)
{
	if (argc != 2) {
		fprintf(stderr, "Usage: <string>");
		exit(1);
	}
	vuln_func(argv[1]);
	return 0;
}
