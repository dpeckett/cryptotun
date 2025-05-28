// SPDX-License-Identifier: GPL-2.0
#include "receive.h"
#include "crypto.h"
#include "device.h"
#include "messages.h"
#include "replay.h"

#define BUF_SIZE 2000

int cryptotun_rx_thread(void *data)
{
	struct net_device *dev = data;
	struct cryptotun_device *tun_dev = netdev_priv(dev);
	struct msghdr msg = {};
	struct kvec iov;
	struct sk_buff *skb;
	void *buf;
	int len;

	if (!tun_dev->udp_sock) {
		dev_put(dev);
		return -ENODEV;
	}

	buf = kmalloc(BUF_SIZE, GFP_KERNEL);
	if (!buf) {
		dev_put(dev);
		return -ENOMEM;
	}

	pr_info(LOG_PREFIX "%s: started for device %s\n", __func__, dev->name);

	while (!kthread_should_stop()) {
		memset(buf, 0, BUF_SIZE);
		memset(&msg, 0, sizeof(msg));
		iov.iov_base = buf;
		iov.iov_len = BUF_SIZE;

		len = kernel_recvmsg(tun_dev->udp_sock, &msg, &iov, 1, BUF_SIZE,
				     MSG_DONTWAIT);
		if (len <= 0) {
			usleep_range(10000, 20000);
			continue;
		}

		pr_debug(LOG_PREFIX "%s: received packet length %d\n", __func__,
			 len);

		if (tun_dev->rx_aead &&
		    len > sizeof(struct cryptotun_header) + TAG_LEN) {
			u8 *plain;
			int plain_len;
			struct cryptotun_header *hdr = buf;

			plain = kmalloc(len - sizeof(*hdr) - TAG_LEN,
					GFP_KERNEL);
			if (!plain)
				continue;

			plain_len = cryptotun_decrypt_packet(
				tun_dev, buf, len, plain,
				len - sizeof(*hdr) - TAG_LEN);
			if (plain_len < 0) {
				pr_warn(LOG_PREFIX
					"%s: decryption failed (%d)\n",
					__func__, plain_len);
				memzero_explicit(plain,
						 len - sizeof(*hdr) - TAG_LEN);
				kfree(plain);
				continue;
			}

			if (be32_to_cpu(hdr->type) != CRYPTOTUN_MSG_TYPE_DATA) {
				pr_warn(LOG_PREFIX
					"%s: unknown message type %u, dropping packet\n",
					__func__, be32_to_cpu(hdr->type));
				memzero_explicit(plain, plain_len);
				kfree(plain);
				continue;
			}

			if (!cryptotun_replay_counter_validate(
				    &tun_dev->rx_counter,
				    be64_to_cpu(hdr->nonce))) {
				pr_warn(LOG_PREFIX
					"%s: packet is a replay, dropping\n",
					__func__);
				memzero_explicit(plain, plain_len);
				kfree(plain);
				continue;
			}

			skb = alloc_skb(plain_len + NET_IP_ALIGN, GFP_KERNEL);
			if (!skb) {
				memzero_explicit(plain, plain_len);
				kfree(plain);
				continue;
			}

			skb_reserve(skb, NET_IP_ALIGN);
			memcpy(skb_put(skb, plain_len), plain, plain_len);
			memzero_explicit(plain, plain_len);
			kfree(plain);

			u8 ip_version = skb->data[0] >> 4;

			skb->dev = dev;
			skb->protocol = (ip_version == 6) ? htons(ETH_P_IPV6) :
							    htons(ETH_P_IP);
			skb->ip_summed = CHECKSUM_UNNECESSARY;

			pr_debug(LOG_PREFIX "%s: passing packet to netif_rx\n",
				 __func__);
			netif_rx(skb);
		}
	}

	kfree(buf);
	dev_put(dev);
	pr_info(LOG_PREFIX "%s: exiting\n", __func__);
	return 0;
}
