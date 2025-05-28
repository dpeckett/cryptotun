// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/slab.h>

#include "crypto.h"
#include "device.h"
#include "messages.h"

#ifndef KUNIT_EXPECT_MEMEQ
#define KUNIT_EXPECT_MEMEQ(test, a, b, len) \
	KUNIT_EXPECT_TRUE(test, memcmp((a), (b), (len)) == 0)
#endif

static struct cryptotun_device *tun_dev;

int cryptotun_crypto_suite_init(struct kunit_suite *suite)
{
	u8 key[KEY_LEN] = { 0 };

	tun_dev = kzalloc(sizeof(*tun_dev), GFP_KERNEL);
	if (!tun_dev)
		return -ENOMEM;

	memset(tun_dev, 0, sizeof(*tun_dev));

	tun_dev->rx_aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tun_dev->rx_aead)) {
		kfree(tun_dev);
		return PTR_ERR(tun_dev->rx_aead);
	}

	crypto_aead_setkey(tun_dev->rx_aead, key, KEY_LEN);
	crypto_aead_setauthsize(tun_dev->rx_aead, TAG_LEN);
	tun_dev->tx_aead = tun_dev->rx_aead;

	return 0;
}

void cryptotun_crypto_suite_exit(struct kunit_suite *suite)
{
	if (!IS_ERR_OR_NULL(tun_dev)) {
		if (tun_dev->rx_aead)
			crypto_free_aead(tun_dev->rx_aead);
		kfree(tun_dev);
	}
}

static void cryptotun_crypto_roundtrip_test(struct kunit *test)
{
	u8 plaintext[64] = "This is test data for encryption";
	u8 ciphertext[128];
	u8 decrypted[64];
	int pkt_len, dec_len;

	pkt_len = cryptotun_encrypt_packet(tun_dev, plaintext,
					   sizeof(plaintext), ciphertext,
					   sizeof(ciphertext));
	KUNIT_ASSERT_GT(test, pkt_len, 0);

	dec_len = cryptotun_decrypt_packet(tun_dev, ciphertext, pkt_len,
					   decrypted, sizeof(decrypted));
	KUNIT_EXPECT_EQ(test, dec_len, (int)sizeof(plaintext));
	KUNIT_EXPECT_MEMEQ(test, plaintext, decrypted, sizeof(plaintext));
}

static void cryptotun_crypto_tamper_ciphertext_test(struct kunit *test)
{
	u8 plaintext[32] = "Tamper test data";
	u8 ciphertext[128];
	int pkt_len, dec_len;
	u8 decrypted[64];

	pkt_len = cryptotun_encrypt_packet(tun_dev, plaintext,
					   sizeof(plaintext), ciphertext,
					   sizeof(ciphertext));
	KUNIT_ASSERT_GT(test, pkt_len, 0);

	/* Tamper with ciphertext (flip a byte) */
	ciphertext[pkt_len - 1] ^= 0xFF;

	dec_len = cryptotun_decrypt_packet(tun_dev, ciphertext, pkt_len,
					   decrypted, sizeof(decrypted));
	KUNIT_EXPECT_LT(test, dec_len, 0); // Expect error due to auth failure
}

static void cryptotun_crypto_tamper_header_test(struct kunit *test)
{
	u8 plaintext[32] = "Nonce tamper data";
	u8 ciphertext[128];
	int pkt_len, dec_len;
	u8 decrypted[64];
	struct cryptotun_header *hdr;

	pkt_len = cryptotun_encrypt_packet(tun_dev, plaintext,
					   sizeof(plaintext), ciphertext,
					   sizeof(ciphertext));
	KUNIT_ASSERT_GT(test, pkt_len, 0);

	hdr = (struct cryptotun_header *)ciphertext;
	hdr->tunnel_id ^= cpu_to_be32(1); // Flip a bit in tunnel_id

	dec_len = cryptotun_decrypt_packet(tun_dev, ciphertext, pkt_len,
					   decrypted, sizeof(decrypted));
	KUNIT_EXPECT_LT(test, dec_len, 0); // Expect error due to IV mismatch
}

static void cryptotun_crypto_truncated_packet_test(struct kunit *test)
{
	u8 plaintext[32] = "Truncated packet data";
	u8 ciphertext[128];
	int pkt_len, dec_len;
	u8 decrypted[64];

	pkt_len = cryptotun_encrypt_packet(tun_dev, plaintext,
					   sizeof(plaintext), ciphertext,
					   sizeof(ciphertext));
	KUNIT_ASSERT_GT(test, pkt_len, 0);

	/* Truncate ciphertext */
	dec_len = cryptotun_decrypt_packet(tun_dev, ciphertext, pkt_len - 5,
					   decrypted, sizeof(decrypted));
	KUNIT_EXPECT_LT(test, dec_len, 0); // Expect error
}

static void cryptotun_crypto_insufficient_output_buffer_test(struct kunit *test)
{
	u8 plaintext[32] = "Short buffer test";
	u8 ciphertext[128];
	int pkt_len, dec_len;
	u8 decrypted[10]; // Too small for output

	pkt_len = cryptotun_encrypt_packet(tun_dev, plaintext,
					   sizeof(plaintext), ciphertext,
					   sizeof(ciphertext));
	KUNIT_ASSERT_GT(test, pkt_len, 0);

	dec_len = cryptotun_decrypt_packet(tun_dev, ciphertext, pkt_len,
					   decrypted, sizeof(decrypted));
	KUNIT_EXPECT_EQ(test, dec_len,
			-EMSGSIZE); // Expect insufficient buffer error
}

static struct kunit_case cryptotun_crypto_test_cases[] = {
	KUNIT_CASE(cryptotun_crypto_roundtrip_test),
	KUNIT_CASE(cryptotun_crypto_tamper_ciphertext_test),
	KUNIT_CASE(cryptotun_crypto_tamper_header_test),
	KUNIT_CASE(cryptotun_crypto_truncated_packet_test),
	KUNIT_CASE(cryptotun_crypto_insufficient_output_buffer_test),
	{}
};

static struct kunit_suite cryptotun_crypto_test_suite = {
	.name = "cryptotun_crypto",
	.suite_init = cryptotun_crypto_suite_init,
	.suite_exit = cryptotun_crypto_suite_exit,
	.test_cases = cryptotun_crypto_test_cases,
};

kunit_test_suite(cryptotun_crypto_test_suite);
