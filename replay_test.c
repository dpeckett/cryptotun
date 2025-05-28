// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>

#include "replay.h"

#define T_LIM (COUNTER_WINDOW_SIZE + 1)

static void test_replay_accepts_first_packet(struct kunit *test)
{
	struct cryptotun_replay_counter counter = {};
	bool res;

	spin_lock_init(&counter.lock);

	res = cryptotun_replay_counter_validate(&counter, 1);
	KUNIT_EXPECT_TRUE(test, res);
}

static void test_replay_rejects_replay(struct kunit *test)
{
	struct cryptotun_replay_counter counter = {};
	bool res;

	spin_lock_init(&counter.lock);

	cryptotun_replay_counter_validate(&counter, 1);
	res = cryptotun_replay_counter_validate(&counter, 1);

	KUNIT_EXPECT_FALSE(test, res);
}

static void test_replay_accepts_newer(struct kunit *test)
{
	struct cryptotun_replay_counter counter = {};

	spin_lock_init(&counter.lock);

	cryptotun_replay_counter_validate(&counter, 1);
	KUNIT_EXPECT_TRUE(test, cryptotun_replay_counter_validate(&counter, 2));
}

static void test_replay_accepts_far_future_packet(struct kunit *test)
{
	struct cryptotun_replay_counter counter = {};

	spin_lock_init(&counter.lock);

	KUNIT_EXPECT_TRUE(test, cryptotun_replay_counter_validate(&counter,
								  T_LIM + 10));
}

static void
test_replay_rejects_old_packet_after_window_advance(struct kunit *test)
{
	struct cryptotun_replay_counter counter = {};
	int i;

	spin_lock_init(&counter.lock);

	for (i = 1; i <= COUNTER_WINDOW_SIZE; ++i)
		KUNIT_EXPECT_TRUE(
			test, cryptotun_replay_counter_validate(&counter, i));

	KUNIT_EXPECT_FALSE(test,
			   cryptotun_replay_counter_validate(&counter, 1));
}

static void test_replay_accepts_backward_unseen_packet(struct kunit *test)
{
	struct cryptotun_replay_counter counter = {};
	u64 latest = COUNTER_WINDOW_SIZE + 10;
	u64 unseen = latest - 5;

	spin_lock_init(&counter.lock);

	KUNIT_EXPECT_TRUE(test,
			  cryptotun_replay_counter_validate(&counter, latest));
	KUNIT_EXPECT_TRUE(test,
			  cryptotun_replay_counter_validate(&counter, unseen));
	KUNIT_EXPECT_FALSE(test,
			   cryptotun_replay_counter_validate(&counter, unseen));
}

static void test_replay_rejects_wraparound(struct kunit *test)
{
	struct cryptotun_replay_counter counter = {};

	spin_lock_init(&counter.lock);

	KUNIT_EXPECT_TRUE(test, cryptotun_replay_counter_validate(
					&counter, REJECT_AFTER_MESSAGES - 1));
	KUNIT_EXPECT_FALSE(test, cryptotun_replay_counter_validate(
					 &counter, REJECT_AFTER_MESSAGES));
	KUNIT_EXPECT_FALSE(test, cryptotun_replay_counter_validate(
					 &counter, REJECT_AFTER_MESSAGES + 1));
}

static struct kunit_case replay_test_cases[] = {
	KUNIT_CASE(test_replay_accepts_first_packet),
	KUNIT_CASE(test_replay_rejects_replay),
	KUNIT_CASE(test_replay_accepts_newer),
	KUNIT_CASE(test_replay_accepts_far_future_packet),
	KUNIT_CASE(test_replay_rejects_old_packet_after_window_advance),
	KUNIT_CASE(test_replay_accepts_backward_unseen_packet),
	KUNIT_CASE(test_replay_rejects_wraparound),
	{}
};

static struct kunit_suite replay_test_suite = {
	.name = "cryptotun_replay",
	.test_cases = replay_test_cases,
};

kunit_test_suite(replay_test_suite);
MODULE_LICENSE("GPL");
