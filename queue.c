#include <stdio.h>
#include <stdlib.h>

#include "queue.h"

// Initialize the queue
void initialize(queue_t *q)
{
    q->head = 0;
    q->tail = 0;
}

// Check if the queue is empty
int is_empty(queue_t *q)
{
    return (q->head == q->tail);
}

// Check if the queue is full
int is_full(queue_t *q)
{
    return ((q->head + 1) % MAX_QUEUE_SIZE == q->tail);
}

// Add an item to the queue
void enqueue(queue_t *q, range_t *r)
{
    if (is_full(q))
    {
        printf("Queue is full!\n");
        exit(1);
    }
    else
    {
        q->items[q->head] = r;
        q->head = (q->head + 1) % MAX_QUEUE_SIZE;
    }
}

// Remove an item from the queue
range_t *dequeue(queue_t *q)
{
    range_t *r;
    if (is_empty(q))
    {
        printf("Queue is empty!\n");
        exit(1);
    }
    else
    {
        r = q->items[q->tail];
        q->tail = (q->tail + 1) % MAX_QUEUE_SIZE;
    }
    return r;
}