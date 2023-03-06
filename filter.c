#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>

#include "filter.h"

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#define VALIDATE_ARCHITECTURE                                         \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, arch_nr),                      \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0), \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL \
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_nr)

#define BLOCK_SYSCALL(nr)                                                          \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1),                                 \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)), \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

void install_basic_filters(int nr, int error)
{
    struct sock_filter filters[] = {
        VALIDATE_ARCHITECTURE,
        EXAMINE_SYSCALL,
        BLOCK_SYSCALL(nr),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filters) / sizeof(filters[0])),
        .filter = filters,
    };
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0)
    {
        perror("Seccomp error");
        exit(1);
    }
}

int bitmap_length(__u32 *bitmap, int n_words)
{
    int n = 0;
    for (int i = 0; i < n_words; i++)
        for (int j = 0; j < BITS_PER_U32; j++)
            n += (bitmap[i] >> j) & 1;
    return n;
}

int *bitmap_to_array(__u32 *bitmap, int n_words, int *allowed)
{
    for (int i = 0; i < n_words; i++)
        for (int j = 0; j < BITS_PER_U32; j++)
            if (bitmap[i] & (1 << j))
                *allowed++ = i * BITS_PER_U32 + j;
    return allowed;
}

__u32 *array_to_bitmap(int *allowed, int n, int n_words)
{
    __u32 *bitmap = calloc(n_words, sizeof(__u32));
    for (int i = 0; i < n; i++)
        bitmap[allowed[i] / BITS_PER_U32] |= 1 << (allowed[i] % BITS_PER_U32);
    return bitmap;
}

void preorder_avl_old(int arr[], int start, int end, int *result, int *index)
{
    int mid;
    if (start > end)
        return;
    mid = (start + end) / 2;
    result[(*index)++] = arr[mid];
    preorder_avl_old(arr, start, mid - 1, result, index);
    preorder_avl_old(arr, mid + 1, end, result, index);
}

typedef struct syscall_node
{
    int nr;
    int left_index;
    int right_index;
} syscall_node_t;

void preorder_avl(int arr[], int start, int end, syscall_node_t *result, int *index)
{
    int mid;
    syscall_node_t *current_node;

    if (start > end)
        return;

    mid = (start + end) / 2;
    current_node = &result[*index];
    result[(*index)++] = (syscall_node_t){arr[mid], -1, -1};
    if (mid > start)
    {
        /* [SN-2023-02-27] Left child exist */
        current_node->left_index = *index;
        preorder_avl(arr, start, mid - 1, result, index);
    }
    if (mid < end)
    {
        /* [SN-2023-02-27] Right child exist */
        current_node->right_index = *index;
        preorder_avl(arr, mid + 1, end, result, index);
    }
}

/* [SN-2023-02-27] Left & right inclusive */
void allowed_to_filters_helper(int arr[], int start, int end, filter_t *filters, int *index, int n)
{
    int mid;
    int line2_index = *index + 1,
        less_index = -1,
        greater_index = -1,
        allow_index = 2 * n;
    int block_index = allow_index + 1;

    if (start > end)
        return;

    mid = (start + end) / 2;
    filters[(*index)++] = (filter_t)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                                             arr[mid],
                                             allow_index - line2_index,
                                             0);
    if (mid > start)
    {
        /* [SN-2023-02-27] Left child exist */
        less_index = ++(*index);
        allowed_to_filters_helper(arr, start, mid - 1, filters, index, n);
    }
    if (mid < end)
    {
        /* [SN-2023-02-27] Right child exist */
        greater_index = ++(*index);
        allowed_to_filters_helper(arr, mid + 1, end, filters, index, n);
    }

    less_index = ((less_index == -1) ? block_index : less_index) - line2_index - 1;
    greater_index = ((greater_index == -1) ? block_index : greater_index) - line2_index - 1;
    filters[line2_index] = (filter_t)BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, arr[mid], greater_index, less_index);
}

/* [SN-2023-02-27] The number of instructions before the actual filters */
#define N_PREINSTRUCTIONS 1
filter_t *allowed_to_filters(int allowed[], int n, int error)
{
    filter_t *filters = malloc(sizeof(filter_t) * (2 * n + 1));
    int index = 0;
    filters = (filter_t *)malloc(sizeof(filter_t) * (n * 2 + N_PREINSTRUCTIONS + 2));
    filters[0] = (filter_t)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_nr);
    /* [SN-2023-02-27] Add more pre instructions here*/

    /* [SN-2023-02-27] Allow and Block instruction */
    filters[2 * n + N_PREINSTRUCTIONS] = (filter_t)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    filters[2 * n + N_PREINSTRUCTIONS + 1] = (filter_t)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA));

    /* [SN-2023-02-27] Hide pre instructions */
    filters += N_PREINSTRUCTIONS;
    allowed_to_filters_helper(allowed, 0, n - 1, filters, &index, n);
    /* [SN-2023-02-27] Unhide pre instructions */
    filters -= N_PREINSTRUCTIONS;
    return filters;
}

void install_avl_filter(__u32 *allowed_bitmap, int n_words, int error)
{
    struct sock_fprog prog;
    filter_t *filters;
    int n = bitmap_length(allowed_bitmap, n_words);
    printf(">>Number of allowed syscalls: %d\n", n);
    int *allowed = (int *)malloc(sizeof(int) * n);

    bitmap_to_array(allowed_bitmap, n_words, allowed);
    printf(">>Allowed syscalls: ");
    for (int i = 0; i < n; i++)
        printf("%d ", allowed[i]);
    printf("\n");

    /* [SN-2023-02-28]  Print out AVL tree in preorder */
    /*
        syscall_node_t *ordered = (syscall_node_t *)malloc(sizeof(syscall_node_t) * n);
        preorder_avl(allowed, 0, n - 1, ordered, &index);

        for (int i = 0; i < n; i++)
            printf("%d\t%d\t%d\n", ordered[i].nr, ordered[i].left_index, ordered[i].right_index);
        free(ordered);
    */

    filters = allowed_to_filters(allowed, n, error);

    /* [SN-2023-02-27] Install filters */
    prog = (struct sock_fprog){
        .len = n * 2 + N_PREINSTRUCTIONS + 2,
        .filter = filters,
    };
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) != 0)
    {
        perror("Seccomp error");
        exit(1);
    }
    /* [SN-2023-02-27] Free heap allocation */
    free(filters);
    free(allowed);
}

__u32 *bpf_to_bitmap(filter_t *filters, int n_words)
{
    __u32 *bitmap = calloc(n_words, sizeof(__u32));
    return bitmap;
}