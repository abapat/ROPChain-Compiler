CC=gcc

all: read

read: read.c
	sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
	gcc -g -fno-stack-protector -o read read.c


clean:
	rm read
