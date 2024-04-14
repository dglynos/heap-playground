DEBUG=-DDEBUG
# DEBUG=

all: repl

repl: repl.c simpleallocator.o
	$(CC) -Wall -g -ggdb ${DEBUG} -o $@ $^ -lreadline

simpleallocator.o: simpleallocator.c simpleallocator.h util.h
	$(CC) -Wall -g -ggdb ${DEBUG} -c simpleallocator.c

clean:
	rm -f simpleallocator.o repl

.PHONY: all
