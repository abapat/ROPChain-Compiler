CC=gcc

all: vuln

vuln: vuln.c
	sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
	gcc -g -fno-stack-protector -mpreferred-stack-boundary=2 -o vuln vuln.c

clean:
	rm vuln
