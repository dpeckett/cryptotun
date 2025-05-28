// SPDX-License-Identifier: GPL-2.0
#include "replay.h"
#include <kunit/test.h>

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

static struct kunit_case replay_test_cases[] = {
	KUNIT_CASE(test_replay_accepts_first_packet),
	KUNIT_CASE(test_replay_rejects_replay),
	KUNIT_CASE(test_replay_accepts_newer),
	{}
};

static struct kunit_suite replay_test_suite = {
	.name = "cryptotun_replay",
	.test_cases = replay_test_cases,
};

kunit_test_suite(replay_test_suite);
MODULE_LICENSE("GPL");
