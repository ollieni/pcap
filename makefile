SHELL = /bin/bash
CC = gcc
CFLAGS = -g -O3 -pthread
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: ${EXE}

%:	%.c
	${CC} ${CFLAGS} $@.c -lpcap -o $@

clean:
	rm ${EXE}

