#include "filter.h"
#include "queue.h"

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

#define BITMAP_SET(bitmap, i) (bitmap[(i) / BITS_PER_U32] |= 1 << ((i) % BITS_PER_U32))
__u32 *array_to_bitmap(int *allowed, int n, int n_words)
{
    __u32 *bitmap = calloc(n_words, sizeof(__u32));
    for (int i = 0; i < n; i++)
        BITMAP_SET(bitmap, allowed[i]);
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
    filter_t *filters;
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

void analyze_range(range_t *range, __u32 *b, queue_t *q)
{
    /* [SN-2023-03-06] In comparison, high is the right boundary of the less range */
    /* [SN-2023-03-06] low is the left boundary of the greater range */
    /* [SN-2023-03-06] K can be included in either or none of the ranges */
    int high, low;
    /* [SN-2023-03-06] if RET_ALLOW, set all bits in range */
    if (range->filters[0].code == (BPF_RET | BPF_K) && range->filters[0].k == SECCOMP_RET_ALLOW)
    {
        for (int i = range->low; i <= range->high; i++)
            BITMAP_SET(b, i);
        return;
    }

    /* [SN-2023-03-06] For other RET instructions, clear bit(do nothing) */
    else if (range->filters[0].code == (BPF_RET | BPF_K))
        return;
    else
    {
        switch (range->filters[0].code)
        {
        case BPF_JMP | BPF_JGT | BPF_K:
            // Greater
            high = MIN(range->filters[0].k, range->high);
            low = MAX(range->filters[0].k + 1, range->low);
            if (low <= range->high)
            {
                range_t *greater_range = (range_t *)malloc(sizeof(range_t));
                greater_range->low = low;
                greater_range->high = range->high;
                greater_range->filters = range->filters + range->filters[0].jt + 1;
                enqueue(q, greater_range);
            }
            // Equal or less
            if (high >= range->low)
            {
                range_t *equal_or_less_range = (range_t *)malloc(sizeof(range_t));
                equal_or_less_range->low = range->low;
                equal_or_less_range->high = high;
                equal_or_less_range->filters = range->filters + range->filters[0].jf + 1;
                enqueue(q, equal_or_less_range);
            }

            break;
        case BPF_JMP | BPF_JGE | BPF_K:
            low = MAX(range->filters[0].k, range->low);
            high = MIN(range->filters[0].k - 1, range->high);
            // Greater or equal
            if (low <= range->high)
            {
                range_t *greater_or_equal_range = (range_t *)malloc(sizeof(range_t));
                greater_or_equal_range->low = low;
                greater_or_equal_range->high = range->high;
                greater_or_equal_range->filters = range->filters + range->filters[0].jt + 1;
                enqueue(q, greater_or_equal_range);
            }
            // Less
            if (high >= range->low)
            {
                range_t *less_range = (range_t *)malloc(sizeof(range_t));
                less_range->low = range->low;
                less_range->high = high;
                less_range->filters = range->filters + range->filters[0].jf + 1;
                enqueue(q, less_range);
            }
            break;
        case BPF_JMP | BPF_JEQ | BPF_K:
            low = MAX(range->filters[0].k + 1, range->low);
            high = MIN(range->filters[0].k - 1, range->high);
            // Equal
            if (range->filters[0].k >= range->low && range->filters[0].k <= range->high)
            {
                range_t *equal_range = (range_t *)malloc(sizeof(range_t));
                equal_range->low = range->filters[0].k;
                equal_range->high = range->filters[0].k;
                equal_range->filters = range->filters + range->filters[0].jt + 1;
                enqueue(q, equal_range);
            }
            // Greater
            if (low <= range->high)
            {
                range_t *greater_range = (range_t *)malloc(sizeof(range_t));
                greater_range->low = low;
                greater_range->high = range->high;
                greater_range->filters = range->filters + range->filters[0].jf + 1;
                enqueue(q, greater_range);
            }
            // Less
            if (high >= range->low)
            {
                range_t *less_range = (range_t *)malloc(sizeof(range_t));
                less_range->low = range->low;
                less_range->high = high;
                less_range->filters = range->filters + range->filters[0].jf + 1;
                enqueue(q, less_range);
            }
            break;
        /* [SN-2023-03-06] If not a constant valued comparison JMP, exit */
        default:
            printf(">>Not a constant-valued comparison JMP\n");
            exit(1);
        }
    }
}

#define __NR_syscall_max 440
__u32 *bpf_to_bitmap(filter_t *filters, int n_words, int m)
{
    __u32 *bitmap = calloc(n_words, sizeof(__u32));

    /* [SN-2023-03-06] Assuming first line is BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_nr) */
    /* [SN-2023-03-06] Otherwise, we can't optimize due to potential jumps and dynamic comparison*/
    /* [SN-2023-03-06] TODO implement a more specific check for 8 Classes of instructions*/
    if (filters[0].code != (BPF_LD | BPF_W | BPF_ABS) || filters[0].k != syscall_nr)
    {
        printf(">>First instruction must load syscall nr\n");
        exit(1);
    }

    /* [SN-2023-03-06] Left and right inclusive */
    queue_t *q = (queue_t *)malloc(sizeof(queue_t));
    initialize(q);

    range_t *range = (range_t *)malloc(sizeof(range_t));
    range->low = 0;
    range->high = __NR_syscall_max;
    range->filters = filters + 1;

    enqueue(q, range);
    while (!is_empty(q))
    {
        range_t *range = dequeue(q);
        analyze_range(range, bitmap, q);
        free(range);
    }

    free(q);
    return bitmap;
}