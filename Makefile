CC=gcc

all: vuln read

vuln: vuln.c
	sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
	gcc -g -fno-stack-protector  -o vuln vuln.c

read: read.c
	sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
	gcc -g -fno-stack-protector  -o read read.c


clean:
	rm vuln read
