/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTOTUN_CRYPTO_H
#define _CRYPTOTUN_CRYPTO_H

#include "device.h"

#define KEY_LEN 16
#define TAG_LEN 16
#define NONCE_LEN 12

int cryptotun_encrypt_packet(struct cryptotun_device *tun_dev, const u8 *in,
			     int in_len, u8 *out, int out_len);

int cryptotun_decrypt_packet(struct cryptotun_device *tun_dev, const u8 *in,
			     int in_len, u8 *out, int out_len);

#endif /* _CRYPTOTUN_CRYPTO_H */
