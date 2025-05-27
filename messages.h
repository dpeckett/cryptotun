/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTOTUN_MESSAGES_H
#define _CRYPTOTUN_MESSAGES_H

#include <linux/types.h>

struct cryptotun_header {
	__be32 type;
	__be32 reserved;
	__be64 nonce;
} __packed;

#endif /* _CRYPTOTUN_MESSAGES_H */
