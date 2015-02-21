CC = gcc
CFLAGS = -std=c99 -m32 -O0 -fno-stack-protector -z execstack

all: echo.c
	$(CC) $(CFLAGS) echo.c echo

clean:
	rm -f *.o echo

.PHONY: clean

