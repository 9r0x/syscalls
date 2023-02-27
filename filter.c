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

void full_binary_search_filter(int nr)
{
    int allowed_min = 19;
    int allowed_max = 200;

    int allowed_len = 10;

    struct sock_filter filters[] =
        {
            VALIDATE_ARCHITECTURE,
            // Memory: size = BPF_MEMWORDS = 16 words -> 16 long int
            // M[0] <- nr
            EXAMINE_SYSCALL,
            BPF_STMT(BPF_ST, 0),
            /* [SN-2023-02-26] Boundary check */
            /* [SN-2023-02-26] A >= min ? stay : abort */
            BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, allowed_min, 1, ABORT),
            /* [SN-2023-02-26] A >= max ? abort: stay */
            BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, allowed_max, ABORT, 0),

            /* [SN-2023-02-26] M[1] <- low */
            BPF_STMT(BPF_LDX | BPF_W | BPF_IMM, allowed_min),
            BPF_STMT(BPF_STX, 1),

            /* [SN-2023-02-26] M[2] <- high */
            BPF_STMT(BPF_LDX | BPF_W | BPF_IMM, allowed_max),
            BPF_STMT(BPF_STX, 2),

            /* [SN-2023-02-26]  */

            /* [SN-2023-02-26] Complete list check */
            /* [SN-2023-02-26] First check if equal, otherwise modify MID */
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, FILTER_0, 0),
            BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 0, GREATER, LESS),

            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, FILTER_1, 0),
            BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 1, GREATER, LESS),

            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 2, FILTER_2, 0),
            BPF_JUMP(BPF_JMP | BPF_JGT | BPF_K, 2, GREATER, LESS),

            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
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