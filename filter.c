#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <errno.h>

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