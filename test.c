#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/prctl.h>

#include "filter.h"

void no_block_test()
{
    printf("\nTest 1: no filter\n");
    // _NR is Numeric Reference
    syscall(SYS_write, 1, "Write 1\tallowed\n", 16);
    syscall(__NR_write, 1, "Write 2\tallowed\n", 16);
}

void *syscall_strict()
{
    syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL);
    printf(">Filters installed\n");
    // write is allowed
    syscall(SYS_write, 1, "Write\tallowed\n", 14);
    syscall(SYS_time, 0);
    printf("Time\tallowed\n");
    return (void *)1;
}

void strict_test()
{
    pthread_t t;
    void *ret;

    printf("\nTest 2: strict filter\n");
    pthread_create(&t, NULL, &syscall_strict, NULL);
    if (pthread_join(t, &ret) < 0)
    {
        perror("pthread_join");
        exit(1);
    }
    // Termination of the calling thread, which seems to return 0
    // SIGSYS is sent, but not sure how it is handled...
    if (ret == 0)
        printf("Time\tblocked\n");
    // now is allowed
    printf(">Filters removed\n");
    int time = syscall(SYS_time, 0);
    printf("Time\tallowed: %d\n", time);
}

#define eno 99
void basic_filter_test()
{
    printf("\nTest 3: custom basic filter\n");
    int time;
    // Before the filter is installed
    time = syscall(SYS_time, 0);
    if (errno != eno)
        printf("Time\tallowed: %d\n", time);
    else
        printf("Time\tblocked\n");

    install_basic_filters(__NR_time, eno);
    printf(">Filters installed\n");
    // After the filter is installed
    time = syscall(SYS_time, 0);
    if (errno != eno)
        printf("Time\tallowed: %d\n", time);
    else
        printf("Time\tblocked\n");
}

int main(void)
{
    no_block_test();
    strict_test();
    basic_filter_test();
    return 0;
}