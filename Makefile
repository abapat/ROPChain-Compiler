CC=gcc

all: vuln

vuln: vuln.c
	sudo bash -c "echo 0 > /proc/sys/kernel/randomize_va_space"
	gcc -g -fno-stack-protector  -o vuln vuln.c

clean:
	rm vuln
