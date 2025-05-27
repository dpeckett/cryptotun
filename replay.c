// SPDX-License-Identifier: GPL-2.0
#include "replay.h"
#include "device.h"

/* This is RFC6479, a replay detection bitmap algorithm that avoids bitshifts */
bool cryptotun_replay_counter_validate(struct cryptotun_replay_counter *counter,
				       u64 their_counter)
{
	unsigned long index, index_current, top, i;
	bool ret = false;

	spin_lock_bh(&counter->lock);

	if (unlikely(counter->counter >= REJECT_AFTER_MESSAGES + 1 ||
		     their_counter >= REJECT_AFTER_MESSAGES))
		goto out;

	++their_counter;

	if (unlikely((COUNTER_WINDOW_SIZE + their_counter) < counter->counter))
		goto out;

	index = their_counter >> ilog2(BITS_PER_LONG);

	if (likely(their_counter > counter->counter)) {
		index_current = counter->counter >> ilog2(BITS_PER_LONG);
		top = min_t(unsigned long, index - index_current,
			    COUNTER_BITS_TOTAL / BITS_PER_LONG);
		for (i = 1; i <= top; ++i)
			counter->backtrack[(i + index_current) &
					   ((COUNTER_BITS_TOTAL / BITS_PER_LONG) -
					    1)] = 0;
		WRITE_ONCE(counter->counter, their_counter);
	}

	index &= (COUNTER_BITS_TOTAL / BITS_PER_LONG) - 1;
	ret = !test_and_set_bit(their_counter & (BITS_PER_LONG - 1),
				&counter->backtrack[index]);

out:
	spin_unlock_bh(&counter->lock);
	return ret;
}
