// SPDX-License-Identifier: GPL-2.0
#include <linux/string.h>

#include "crypto.h"

void generate_iv(u64 nonce, u8 *iv)
{
	memset(iv, 0, NONCE_LEN);
	memcpy(iv + 4, &nonce, sizeof(nonce));
}
