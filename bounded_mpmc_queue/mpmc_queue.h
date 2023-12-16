/*
 * Copyright (c) 2023 Dorjoy Chowdhury
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef MPMC_QUEUE_H
#define MPMC_QUEUE_H

#include <stddef.h>
#include <stdint.h>

#define CACHELINE_SIZE 64

struct queue_entry {
	size_t seq;
	void *data;
};

/*
 * The paddings are necessary to prevent false cacheline sharing among threads
 * which would cause cache coherency traffic among cpu cores.
 */
struct mpmc_queue {
	uint8_t pad0[CACHELINE_SIZE];
	struct queue_entry *queue;
    size_t queue_mask;
	uint8_t pad1[CACHELINE_SIZE];
	size_t enqueue_pos;
	uint8_t pad2[CACHELINE_SIZE];
	size_t dequeue_pos;
	uint8_t pad3[CACHELINE_SIZE];
};

#endif /* MPMC_QUEUE_H */
