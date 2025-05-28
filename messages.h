/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTOTUN_MESSAGES_H
#define _CRYPTOTUN_MESSAGES_H

#include <linux/types.h>

// Known message types
enum cryptotun_msg_type {
	CRYPTOTUN_MSG_TYPE_INVALID = 0,
	// Data message type, used for encrypted data packets
	CRYPTOTUN_MSG_TYPE_DATA = 1,
};

// Header for all cryptotun messages
struct cryptotun_header {
	// Message type, e.g., CRYPTOTUN_MSG_TYPE_DATA
	__be32 type;
	// ID for the tunnel
	__be32 tunnel_id;
	// Message nonce / peers transmit counter
	__be64 nonce;
} __packed;

#endif /* _CRYPTOTUN_MESSAGES_H */
