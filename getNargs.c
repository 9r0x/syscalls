#include <stdio.h>
#include <stdlib.h>

#ifndef __NR_syscall
#define __NR_syscall 500
#endif

int main(int argc, char *argv[])
{
    short syscall[__NR_syscall];
    int nr = 0;
    const char *file_path = "syscall.txt";
    FILE *fp = fopen(file_path, "r");
    char line[20];
    char *p = NULL;
    if (fp == NULL)
        printf("open file %s failed", file_path);

    for (int nr = 0; nr < __NR_syscall; nr++)
        syscall[nr] = -1;

    while (fgets(line, sizeof(line), fp))
    {
        nr = atoi(line);
        p = line;
        while (*p != ' ')
            p++;
        *p = '\0';

        if (nr > __NR_syscall)
            printf("syscall number %d is too big", nr);

        if (*(p + 1) == '\n')
            syscall[nr] = -1;
        else
            syscall[nr] = (short)atoi(p + 1);
    }

    printf("short syscall[] = {");
    for (int i = 0; i < __NR_syscall; i++)
        printf("%hd,", syscall[i]);
    printf("};");

    return 0;
}