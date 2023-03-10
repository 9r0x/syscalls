#include <linux/seccomp.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/utsname.h>

#include "filter.h"

void no_block_test(void)
{
    printf("\nTest 1: no filter\n");
    /* [SN-2023-02-22] _NR is Numeric Reference */
    /* [SN-2023-03-10] Extra arguments are ignored */
    syscall(SYS_write, 1, "Write 1\tallowed\n", 16, 506, "NONONO", (int *)0x12345678);
    syscall(__NR_write, 1, "Write 2\tallowed\n", 16);
}

void *syscall_strict(void *arg)
{
    syscall(SYS_seccomp, SECCOMP_SET_MODE_STRICT, 0, NULL);
    printf(">Filters installed\n");
    syscall(SYS_write, 1, "Write\tallowed\n", 14);
    syscall(SYS_time, 0);
    printf("Time\tallowed\n");
    return (void *)1;
}

void strict_test(void)
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
    /* [SN-2023-02-28] Write is allowed in original thread */
    printf(">Filters removed\n");
    int time = syscall(SYS_time, 0);
    printf("Time\tallowed: %d\n", time);
}

#define eno 99
void basic_filter_test(void)
{
    int time;
    printf("\nTest 3: custom basic filter\n");
    /* [SN-2023-02-28] Before the filter is installed */
    time = syscall(SYS_time, 0);
    if (errno != eno)
        printf("Time\tallowed: %d\n", time);
    else
        printf("Time\tblocked\n");

    install_basic_filters(__NR_time, eno);
    printf(">Filters installed\n");
    /* [SN-2023-02-28] After the filter is installed */
    time = syscall(SYS_time, 0);
    if (errno != eno)
        printf("Time\tallowed: %d\n", time);
    else
        printf("Time\tblocked\n");
    printf("\n");
}

#define N_SYSCALLS 512
#define N_WORDS (N_SYSCALLS / BITS_PER_U32 + N_SYSCALLS % BITS_PER_U32)

void avl_filter_test(void)
{
    int time;
    struct utsname *buf = malloc(sizeof(struct utsname));
    int a[] = {0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 24, 25, 28, 32, 39, 41, 42, 44, 45, 47, 49, 51, 54, 60, 62, 72, 79, 96, 99, 186, 201, 202, 217, 228, 231, 234, 257, 262, 302};
    int n = sizeof(a) / sizeof(int);
    __u32 *b = array_to_bitmap(a, n, N_WORDS);
    printf("\nTest 4: custom avl filter\n");

    /* [SN-2023-02-28] Before the filter is installed */
    syscall(SYS_uname, buf);
    if (errno != eno)
        printf("Uname(63)\tallowed: %s - %s\n", buf->sysname, buf->version);
    else
        printf("Uname(63)\tblocked\n");

    printf(">Filters installed\n");
    install_avl_filter(b, N_WORDS, eno);
    /* [SN-2023-02-28] After the filter is installed */
    syscall(SYS_write, 1, "Write\t\tallowed\n", 15);
    time = syscall(SYS_time, 0);
    if (errno != eno)
        printf("Time(201)\tallowed: %d\n", time);
    else
        printf("Time(201)\tblocked\n");
    syscall(SYS_uname, buf);
    if (errno != eno)
        printf("Uname(63)\tallowed: %s - %sn", buf->sysname, buf->version);
    else
        printf("Uname(63)\tblocked\n");
    printf("\n");
}

void bpf_to_bitmap_test(void)
{
    printf("\nTest 5: bpf to bitmap\n");
    /* [SN-2023-03-06] Step 1: creating a true bitmap */
    int a[] = {0, 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 24, 25, 28, 32, 39, 41, 42, 44, 45, 47, 49, 51, 54, 60, 62, 72, 79, 96, 99, 186, 201, 202, 217, 228, 231, 234, 257, 262, 302};
    int n = sizeof(a) / sizeof(int);
    __u32 *true_bitmap = array_to_bitmap(a, n, N_WORDS);

    /* [SN-2023-03-06] Step 2: Convert the array to BPF filters */
    filter_t *f = allowed_to_filters(a, n, 99);
    /* [SN-2023-03-06] Step 3: Analyze BPF fillters to extract bitmap */
    __u32 *extracted_bitmap = bpf_to_bitmap(f, N_WORDS, 2 * n + 3);

    /* [SN-2023-03-06] Step 4: Examine the bitmap by converting to array*/
    int extracted_bitmap_size = bitmap_length(extracted_bitmap, N_WORDS);
    int *arr = calloc(extracted_bitmap_size, sizeof(int));
    bitmap_to_array(extracted_bitmap, N_WORDS, arr);

    printf("True bitmap: \t\t");
    for (int i = 0; i < n; i++)
        printf("%d ", arr[i]);
    printf("\n");
    printf("Extracted bitmap: \t");
    for (int i = 0; i < n; i++)
        printf("%d ", arr[i]);
    printf("\n");
    free(arr);

    /* [SN-2023-03-06] Step 5: without knowing n, we can still compare two bitmaps */
    for (int i = 0; i < N_WORDS; i++)
    {
        if (true_bitmap[i] != extracted_bitmap[i])
        {
            printf("Bitmaps are different at index %d", i);
            exit(1);
        }
    }
    printf("Bitmaps are the same");
}

void arity_filter_test(void)
{
    struct utsname *buf = malloc(sizeof(struct utsname));
    printf("\nTest 6: arity filter\n");

    /* [SN-2023-03-10] Before the filter is installed */
    syscall(SYS_uname, buf);
    if (errno != eno)
        printf("Uname(63)\tallowed: %s - %s\n", buf->sysname, buf->version);
    else
        printf("Uname(63)\tblocked\n");

    install_arity_filters(__NR_uname, 1, eno);
    printf(">Filters installed\n");

    /* [SN-2023-03-10] After the filter is installed */
    syscall(SYS_uname, buf, 0, 0, 0, 0, 0);
    if (errno != eno)
        printf("Uname(63)\tallowed: %s - %s\n", buf->sysname, buf->version);
    else
        printf("Uname(63)\tblocked\n");

    /* [SN-2023-03-10] ERROR: the excessive args will also be copied to seccomp_data? */
    /* [SN-2023-03-10] Unless we set it to 0, we can't tell excessive args from memory junks */
    /* [SN-2023-03-10] Wrapper prevents misuse */
    /* [SN-2023-03-10] Without wrapper, impossible to tell if arity is right */
    syscall(SYS_uname, buf);
    if (errno != eno)
        printf("Uname(63)\tallowed: %s - %s\n", buf->sysname, buf->version);
    else
        printf("Uname(63)\tblocked\n");

    printf("\n");
}

int main(void)
{
    /* [SN-2023-03-10] Fail to pass extra arguments in wrapper */
    // write(1, "Hello, world", 12, 506, "NONONO", (int *)0x12345678);
    write(1, "Hello, world", 12);
    no_block_test();
    // strict_test();
    // basic_filter_test();
    // avl_filter_test();
    // bpf_to_bitmap_test();
    arity_filter_test();
    return 0;
}
