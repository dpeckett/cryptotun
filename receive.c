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
	int len, plain_len;

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
				     0);
		if (len < 0) {
			pr_warn(LOG_PREFIX "%s: kernel_recvmsg failed: %d\n",
				__func__, len);
			continue;
		}

		if (tun_dev->rx_aead &&
		    len > sizeof(struct cryptotun_header) + TAG_LEN) {
			struct cryptotun_header *hdr = buf;
			int payload_len = len - sizeof(*hdr) - TAG_LEN;

			skb = alloc_skb(payload_len + NET_IP_ALIGN, GFP_KERNEL);
			if (!skb) {
				pr_warn(LOG_PREFIX
					"%s: failed to allocate skb\n",
					__func__);
				continue;
			}

			skb_reserve(skb, NET_IP_ALIGN);
			u8 *data_ptr = skb_put(skb, payload_len);

			plain_len = cryptotun_decrypt_packet(
				tun_dev, buf, len, data_ptr, payload_len);
			if (plain_len < 0) {
				pr_warn(LOG_PREFIX
					"%s: decryption failed (%d)\n",
					__func__, plain_len);
				kfree_skb(skb);
				continue;
			}

			if (be32_to_cpu(hdr->type) != CRYPTOTUN_MSG_TYPE_DATA) {
				pr_warn(LOG_PREFIX
					"%s: unknown message type %u, dropping packet\n",
					__func__, be32_to_cpu(hdr->type));
				continue;
			}

			if (!cryptotun_replay_counter_validate(
				    &tun_dev->rx_counter,
				    be64_to_cpu(hdr->nonce))) {
				pr_warn(LOG_PREFIX
					"%s: packet is a replay, dropping\n",
					__func__);
				continue;
			}

			u8 ip_version = data_ptr[0] >> 4;

			skb->dev = dev;
			skb->protocol = (ip_version == 6) ? htons(ETH_P_IPV6) :
							    htons(ETH_P_IP);
			skb->ip_summed = CHECKSUM_UNNECESSARY;

			netif_rx(skb);
		}
	}

	kfree(buf);
	dev_put(dev);
	pr_info(LOG_PREFIX "%s: exiting\n", __func__);
	return 0;
}
