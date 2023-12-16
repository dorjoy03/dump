/*
 * Copyright (c) 2023 Dorjoy Chowdhury
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef INT_MPMC_QUEUE_H
#define INT_MPMC_QUEUE_H

#include <stddef.h>

struct int_mpmc_queue;

struct int_mpmc_queue *int_mpmc_queue_init(size_t queue_length);
void int_mpmc_queue_free(struct int_mpmc_queue *Q);
int int_mpmc_queue_enqueue(struct int_mpmc_queue *Q, int data);
int int_mpmc_queue_dequeue(struct int_mpmc_queue *Q, int *data);

#endif /* INT_MPMC_QUEUE_H */
