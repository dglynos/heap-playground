# Heap Playground

## Introduction

Over the years of teaching the Software Security postgraduate module 
at cs.unipi.gr we had a number of requests from students who wished
to see how heap buffer overflow exploitation worked in more detail.

This was a topic that we only briefly touched upon in the lectures
but students didn't get the chance to view the mechanics of, or practice
on (through a workshop etc.).

In 2024 I did a revamp of the lecture material and decided that perhaps
if I had all material ready for such a buffer overflow I could quickly
showcase it in class.

To do this I needed a very simplistic **allocator**:
- One that intermingled heap metadata with heap data.
- One that worked on pages with RWX permissions by default.
- One that did minimal initialization to heap data / heap metadata.
- One that provided first-fit blocks in a deterministic manner.

Although this is nowhere near the allocator you'll find today in your C library
or browser, it is simple enough:
- for the students to grasp its implementation
- to showcase what you get when you have an information leak in the heap
- to showcase how you can play around with a deterministic allocator to bring structures in front of others (like *heap feng shui*)
- to imagine what will occur if specific heap metadata become corrupted

The allocator also comes with some verbose debugging (if you define the DEBUG symbol during compilation).

Next, I needed an example **application**. One that we could interact with
and dynamically create structures in heap memory. I decided to go for a very
simplistic REPL (read-eval-print loop).

The `repl` application supports the following functionalities:
- printing the value of a variable, by entering its name (e.g. `a`)
- assigning a value to a variable in hexadecimal format (e.g. `a = \x01\x02\x03\x04\x05`)
- copying the value of one variable to another (e.g. `a = b`)
- exiting the REPL through the `exit` command

## Intended Bugs

The `repl` application has two bugs, on purpose:
1. when assigning a new value to an existing variable, the length of the variable value is not corrected to that of the new value (allowing for information disclosure when
printing the variable value)
2. when copying the value from `variable2` to an existing `variable1` it incorrectly allocates memory for the new variable value, allocating the number of bytes required for the `variable2` name instead.

With these two bugs students can discover:
- how the exploitation of a bug may inform the attacker of the actual memory regions used by the program, which can later be used to determine the exact location of things on the heap (and/or the executable) thus defeating ASLR measures
- how the printing functionality for a variable value, that depends on a function pointer in the variable structure, may become a pivot point for an attacker as the overwrite of the function pointer will allow control of the program execution
- how heap metadata values can be considered as parametric values, when the memory allocator is deterministic

## Compiling the program and its allocator

The application should build OK on any Linux distribution. I haven't tried
it on BSD etc.

Clone this repository and make sure you have the necessary header files available to link against the *readline* library (e.g. on Debian you'll need package `libreadline-dev`).

Make sure you also have your build essentials, like `make` and `gcc`.

```
$ make
cc -Wall -g -ggdb -DDEBUG -c simpleallocator.c
cc -Wall -g -ggdb -DDEBUG -o repl repl.c simpleallocator.o -lreadline

## Running the REPL

$ ./repl
new zone on freelist 0x7fa15b57d018 data 0x7fa15b57d030 len 102352
found spot for 2, 0x7fa15b57d018 len 102352
split off 0x7fa15b57d032 len 102326
freelist item 0x7fa15b57d032 data 0x7fa15b57d04a len 102326 next (nil)
found spot for 1, 0x7fa15b57d032 len 102326
split off 0x7fa15b57d04b len 102301
freelist item 0x7fa15b57d04b data 0x7fa15b57d063 len 102301 next (nil)
found spot for 40, 0x7fa15b57d04b len 102301
split off 0x7fa15b57d08b len 102237
freelist item 0x7fa15b57d08b data 0x7fa15b57d0a3 len 102237 next (nil)
> b = a
found spot for 2, 0x7fa15b57d08b len 102237
split off 0x7fa15b57d0a5 len 102211
freelist item 0x7fa15b57d0a5 data 0x7fa15b57d0bd len 102211 next (nil)
found spot for 2, 0x7fa15b57d0a5 len 102211
split off 0x7fa15b57d0bf len 102185
freelist item 0x7fa15b57d0bf data 0x7fa15b57d0d7 len 102185 next (nil)
free 0x7fa15b57d0a5, placed first on freelist
freelist item 0x7fa15b57d0a5 data 0x7fa15b57d0bd len 2 next 0x7fa15b57d0bf
freelist item 0x7fa15b57d0bf data 0x7fa15b57d0d7 len 102185 next (nil)
found spot for 40, 0x7fa15b57d0bf len 102185
split off 0x7fa15b57d0ff len 102121
freelist item 0x7fa15b57d0a5 data 0x7fa15b57d0bd len 2 next 0x7fa15b57d0ff
freelist item 0x7fa15b57d0ff data 0x7fa15b57d117 len 102121 next (nil)
found spot for 1, 0x7fa15b57d0a5 len 2
freelist item 0x7fa15b57d0ff data 0x7fa15b57d117 len 102121 next (nil)
> b
found spot for 2, 0x7fa15b57d0ff len 102121
split off 0x7fa15b57d119 len 102095
freelist item 0x7fa15b57d119 data 0x7fa15b57d131 len 102095 next (nil)
"\x01"
free 0x7fa15b57d0ff, placed first on freelist
freelist item 0x7fa15b57d0ff data 0x7fa15b57d117 len 2 next 0x7fa15b57d119
freelist item 0x7fa15b57d119 data 0x7fa15b57d131 len 102095 next (nil)
> exit
$ 
```

The debugging messages you see about freelist objects, can be turned
off through the Makefile (comment out the first line in the Makefile and uncomment the second). Rebuild and you'll simply get the `repl` program
output.

## Exploit

`heap-exploit.py` contains exploit code that:
- triggers the first bug to identify where structures have been placed on the heap
- triggers the second bug to copy malicious metadata and shellcode on the heap
- causes the malicious function pointer to be triggered by printing the name of a variable (`aaaaaaaa`)

The script requires a Python 3.x interpreter.            

Example run

```
$ ./heap-exploit.py
Sending...

a
aa
aaa
aaaa
...
(press enter twice)

Time to test our shell!
> cat /etc/motd

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.

(press ctrl+c to terminate)
```

## Dockerfile

There's also a Dockerfile to create a Debian 12 environment for building
the REPL from source.

```
$ docker build -t heap-playground .
$ docker run -v .:/heap -it heap-playground /bin/bash
# cd /heap
# make 
...
```

## Work in progress

I'm currently in the process of forming some diagrams for the operation
of the allocator, the program and the exploit.

These should make presenting this PoC even easier.

## Copyright and license

Heap Playground © 2024 by Dimitrios Glynos is licensed under Creative Commons Attribution-ShareAlike 4.0 International license (see LICENSE file).
