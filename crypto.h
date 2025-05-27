/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTOTUN_CRYPTO_H
#define _CRYPTOTUN_CRYPTO_H

#include <linux/types.h>

#define KEY_LEN 16
#define TAG_LEN 16
#define NONCE_LEN 12

void generate_iv(u64 nonce, u8 *iv);

#endif /* _CRYPTOTUN_CRYPTO_H */
