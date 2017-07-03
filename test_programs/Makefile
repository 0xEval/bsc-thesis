CC=movcc
CFLAGS=-m32
SRCS = $(wildcard *.c)
OBJS=$(SRCS:.c=.o)
PROGS = $(patsubst %.c,%,$(SRCS))

all: $(PROGS)

movcc: $(OBJS)

%: %.c
	gcc $(CFLAGS) -o $@ $<
clean: 
	rm -f $(OBJS) $(PROGS)
