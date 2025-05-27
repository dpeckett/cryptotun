/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTOTUN_DEVICE_H
#define _CRYPTOTUN_DEVICE_H

#include <crypto/aead.h>
#include <linux/crypto.h>
#include <linux/in6.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "replay.h"

#define LOG_PREFIX "[cryptotun] "

struct cryptotun_priv {
	struct socket *udp_sock;
	struct task_struct *rx_thread;
	struct task_struct *tx_thread;
	struct sk_buff_head tx_queue;
	wait_queue_head_t tx_wq;
	__be16 remote_port;
	__be16 local_port;
	bool use_ipv6;
	union {
		__be32 remote_ip4;
		struct in6_addr remote_ip6;
	};

	struct crypto_aead *tx_aead;
	struct crypto_aead *rx_aead;
	u32 nonce_prefix;
	u64 nonce_counter;
	spinlock_t nonce_lock; // Spinlock to protect nonce_counter
	struct cryptotun_replay_counter replay_counter;
};

void cryptotun_setup(struct net_device *dev);

#endif /* _CRYPTOTUN_DEVICE_H */
