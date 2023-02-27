#pragma once

#define BITS_PER_U32 (sizeof(__u32) * 8)

void install_basic_filters(int nr, int error);
__u32 *array_to_bitmap(int *allowed, int n, int n_words);
void install_binary_search_filter(__u32 *allowed_bitmap, int n_words, int error);
