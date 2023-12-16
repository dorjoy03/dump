/*
 * Copyright (c) 2023 Dorjoy Chowdhury
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * This is a C implementation of Dmitry Vyukov's "Bounded MPMC Queue" using gcc
 * atomic builtins. This is almost a line by line C translation with a few
 * tweaks here and there.
 * Ref: https://www.1024cores.net/home/lock-free-algorithms/queues/bounded-mpmc-queue
 *
 * My commentary: The expressions around "pos" in enqueue and dequeue functions
 * like "pos + mask + 1" or "pos + 1" will wrap around if they run enough times
 * but it's fine. Because in the next iterations "enqueue_pos" and "dequeue_pos"
 * will wrap around too. So the wrap around of "pos" or "enqueue_pos" or
 * "dequeue_pos" are equivalent to if they don't wrap around at all.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include "mpmc_queue.h"

/*
 * Initialize queue.
 *
 * ${queue_length} must be some positive power of two value.
 * Returns a valid "handle" to be used in enqueue, dequeue, free functions.
 * Otherwise returns NULL on error.
 */
struct mpmc_queue *
mpmc_queue_init(size_t queue_length)
{
	assert(queue_length >= 2 && (queue_length & (queue_length - 1)) == 0);
	assert(queue_length <= SIZE_MAX / sizeof(struct queue_entry));

	struct mpmc_queue *Q = malloc(sizeof(struct mpmc_queue));
	if (Q == NULL)
		goto err0;

	size_t size = queue_length * sizeof(struct queue_entry);
	struct queue_entry *queue = malloc(size);
	if (queue == NULL)
		goto err1;

	Q->queue = queue;
	Q->queue_mask = queue_length - 1;

	for (size_t i = 0; i < queue_length; ++i) {
		__atomic_store_n(&Q->queue[i].seq, i, __ATOMIC_RELAXED);
	}
	__atomic_store_n(&Q->enqueue_pos, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&Q->dequeue_pos, 0, __ATOMIC_RELAXED);

	return Q;

 err1:
	free(Q);

 err0:
	return NULL;
}

/*
 * Free queue.
 */
void
mpmc_queue_free(struct mpmc_queue *Q)
{
	if (Q != NULL) {
		free(Q->queue);
		free(Q);
	}
	return;
}

/*
 * Enqueue ${data}.
 *
 * Returns 0 if ${data} is successfully enqueued. Otherwise returns -1 when queue
 * is full.
 */
int
mpmc_queue_enqueue(struct mpmc_queue *Q, void *data)
{
	struct queue_entry *entry;
	size_t mask = Q->queue_mask;
	size_t pos = __atomic_load_n(&Q->enqueue_pos, __ATOMIC_RELAXED);

	while(true) {
		entry = &Q->queue[pos & mask];
		size_t seq = __atomic_load_n(&entry->seq, __ATOMIC_ACQUIRE);

		if (seq == pos) {
			if (__atomic_compare_exchange_n(&Q->enqueue_pos, &pos, pos + 1, true,
			                                __ATOMIC_RELAXED, __ATOMIC_RELAXED))
				break;
		} else if (seq < pos) {
			return -1;
		} else {
			pos = __atomic_load_n(&Q->enqueue_pos, __ATOMIC_RELAXED);
		}
	}

	entry->data = data;
	__atomic_store_n(&entry->seq, pos + 1, __ATOMIC_RELEASE);

	return 0;
}

/*
 * Dequeue next queue entry into ${*data}.
 *
 * Returns 0 when an entry is successfully dequeued. Otherwise returns -1 when
 * queue is empty.
 */
int
mpmc_queue_dequeue(struct mpmc_queue *Q, void **data)
{
	struct queue_entry *entry;
	size_t mask = Q->queue_mask;
	size_t pos = __atomic_load_n(&Q->dequeue_pos, __ATOMIC_RELAXED);

	while(true) {
		entry = &Q->queue[pos & mask];
		size_t seq = __atomic_load_n(&entry->seq, __ATOMIC_ACQUIRE);

		if (seq == (size_t)(pos + 1)) {
			if (__atomic_compare_exchange_n(&Q->dequeue_pos, &pos, pos + 1, true,
			                                __ATOMIC_RELAXED, __ATOMIC_RELAXED))
			    break;
		} else if (seq < (size_t)(pos + 1)) {
			return -1;
		} else {
			pos = __atomic_load_n(&Q->dequeue_pos, __ATOMIC_RELAXED);
		}
	}

	*data = entry->data;
	__atomic_store_n(&entry->seq, pos + mask + 1, __ATOMIC_RELEASE);

	return 0;
}
