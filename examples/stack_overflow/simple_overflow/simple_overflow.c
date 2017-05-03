#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void exec_shell()
{
	printf("Spawning a shell\n");
	system("/bin/sh");
}

void vuln_func(char * string)
{
	char buffer[100];
	strcpy(buffer, string);
}

int main(int argc, char* argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: <string>");
		exit(1);
	}
	vuln_func(argv[1]);
	return 0;
}
