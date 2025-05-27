/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTOTUN_REPLAY_COUNTER_H
#define _CRYPTOTUN_REPLAY_COUNTER_H

#include <linux/spinlock.h>
#include <linux/types.h>

#define COUNTER_BITS_TOTAL 8192
#define COUNTER_REDUNDANT_BITS BITS_PER_LONG
#define COUNTER_WINDOW_SIZE (COUNTER_BITS_TOTAL - COUNTER_REDUNDANT_BITS)

#define REJECT_AFTER_MESSAGES (U64_MAX - COUNTER_WINDOW_SIZE - 1)

struct cryptotun_replay_counter {
	u64 counter;
	spinlock_t lock; // Spinlock to protect the counter
	unsigned long backtrack[COUNTER_BITS_TOTAL / BITS_PER_LONG];
};

bool cryptotun_replay_counter_validate(struct cryptotun_replay_counter *counter,
				       u64 their_counter);

#endif /* _CRYPTOTUN_REPLAY_COUNTER_H */
