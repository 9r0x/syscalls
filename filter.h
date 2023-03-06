#pragma once

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>
typedef struct sock_filter filter_t;
#define BITS_PER_U32 (sizeof(__u32) * 8)

void install_basic_filters(int nr, int error);
__u32 *array_to_bitmap(int *allowed, int n, int n_words);
void install_avl_filter(__u32 *allowed_bitmap, int n_words, int error);
filter_t *allowed_to_filters(int allowed[], int n, int error);
int *bitmap_to_array(__u32 *bitmap, int n_words, int *allowed);
__u32 *bpf_to_bitmap(filter_t *filters, int n_words, int m);
int bitmap_length(__u32 *bitmap, int n_words);

typedef struct range
{
    int low;
    int high;
    filter_t *filters;
} range_t;

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

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))