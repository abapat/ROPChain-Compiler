#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

int main() {
    char buf[4];
    int fd;
    fd = open("in.txt", O_RDONLY);
    read(fd, buf, 64);
    return 0;
}

