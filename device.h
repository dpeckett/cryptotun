/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTOTUN_DEVICE_H
#define _CRYPTOTUN_DEVICE_H

#include <crypto/aead.h>
#include <linux/atomic.h>
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

struct cryptotun_device {
	struct socket *udp_sock;
	struct task_struct *rx_thread;
	spinlock_t tx_queue_lock; // Lock for the tx_queue
	struct sk_buff_head tx_queue;
	struct delayed_work tx_work;
	__be16 local_port;
	bool use_ipv6;
	union {
		struct sockaddr_in remote_addr;
		struct sockaddr_in6 remote_addr6;
	};

	struct crypto_aead *tx_aead;
	struct crypto_aead *rx_aead;
	u32 nonce_prefix;
	atomic64_t tx_counter;
	struct cryptotun_replay_counter rx_counter;
};

void cryptotun_setup(struct net_device *dev);

#endif /* _CRYPTOTUN_DEVICE_H */
