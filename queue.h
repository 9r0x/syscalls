#pragma once

#include "filter.h"
#define MAX_QUEUE_SIZE 200
// Define the queue struct
typedef struct queue
{
    /* [SN-2023-03-06] Enqueued at head */
    int head;
    /* [SN-2023-03-06] Dequeued at tail */
    int tail;
    range_t *items[MAX_QUEUE_SIZE];
} queue_t;

void initialize(queue_t *q);
int is_empty(queue_t *q);
int is_full(queue_t *q);
void enqueue(queue_t *q, range_t *r);
range_t *dequeue(queue_t *q);