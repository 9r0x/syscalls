#pragma once

typedef struct sock_filter filter_t;
#define BITS_PER_U32 (sizeof(__u32) * 8)

void install_basic_filters(int nr, int error);
__u32 *array_to_bitmap(int *allowed, int n, int n_words);
void install_avl_filter(__u32 *allowed_bitmap, int n_words, int error);
filter_t *allowed_to_filters(int allowed[], int n, int error);
int *bitmap_to_array(__u32 *bitmap, int n_words, int *allowed);
__u32 *bpf_to_bitmap(filter_t *filters, int n_words);
