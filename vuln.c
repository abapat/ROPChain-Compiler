#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char* argv[]) {
    char buf[256];

    memcpy(buf, argv[1], 300);
    //printf("Input: %s\n", buf);

    return 0;
}

