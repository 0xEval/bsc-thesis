#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//Vulnerability: Buffer Overflow
//Goal: Call add_sh() -> add_bin() -> exec_command()
//Payload:
//	
//	We control the stack and push the key args to pass the tests.
//	A pop; ret; gadget is inserted as a return addr of the function
//	so that the argument is removed from the stack and the program
//	returns to the next gadget (gadget chaining).
//
//	+-----------------------------+
//	|            stack            |
//	+-----------------------------+
//	| <address of exec_command()> |
//	| 0xcafebabe <key1>           | 
//	| 0x8badfood <key2>	      | 
//	| <address of POP; POP; RET>  | 
//	| <address of add_sh()>       |
//	| 0xdeadbeef <key>            | <argument>
//	| <address of POP; RET>       | <return addr>
//	| <address of add_bin()>      | <function call>
//	| 0x42424242 <fake old %ebp>  |
//	| 0x41414141 ...              |
//	|   ... (0x6c bytes of 'A's)  |
//	|   ... 0x41414141            | 0x41414141 == "AAAA"


char command[100];

void exec_command() {
    system(command);
}

void add_bin(int key) {
    if (key == 0xdeadbeef) {
        strcat(command, "/bin");
    }
}

void add_sh(int key1, int key2) {
    if (key1 == 0xcafebabe && key2 == 0x8badf00d) {
        strcat(command, "/sh");
    }
}

void vuln_func(char* string) {
    char buffer[100];
    strcpy(buffer, string);
}

int main(int argc, char** argv) {
    command[0] = 0;
    vuln_func(argv[1]);
    return 0;
}


