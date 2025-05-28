// SPDX-License-Identifier: GPL-2.0
#include "crypto.h"
#include "device.h"
#include "messages.h"

int cryptotun_tx_thread(void *data)
{
	struct net_device *dev = data;
	struct cryptotun_device *tun_dev = netdev_priv(dev);

	pr_info(LOG_PREFIX "%s: TX thread started for device %s\n", __func__,
		dev->name);

	while (!kthread_should_stop()) {
		wait_event_interruptible(tun_dev->tx_wq,
					 !skb_queue_empty(&tun_dev->tx_queue) ||
						 kthread_should_stop());

		while (!skb_queue_empty(&tun_dev->tx_queue)) {
			struct sk_buff *skb = skb_dequeue(&tun_dev->tx_queue);
			struct msghdr msg = {};
			struct kvec iov;
			u8 *inbuf = NULL, *outbuf = NULL;
			int data_len = skb->len;
			int total_len;
			int ret;

			inbuf = kmemdup(skb->data, data_len, GFP_KERNEL);
			if (!inbuf) {
				dev_kfree_skb(skb);
				continue;
			}

			outbuf = kmalloc(sizeof(struct cryptotun_header) +
						 data_len + TAG_LEN,
					 GFP_KERNEL);
			if (!outbuf) {
				kfree(inbuf);
				dev_kfree_skb(skb);
				continue;
			}

			ret = cryptotun_encrypt_packet(
				tun_dev, inbuf, data_len, outbuf,
				sizeof(struct cryptotun_header) + data_len +
					TAG_LEN);

			kfree(inbuf);

			if (ret < 0) {
				pr_warn(LOG_PREFIX
					"%s: Encryption failed (%d)\n",
					__func__, ret);
				kfree(outbuf);
				dev_kfree_skb(skb);
				continue;
			}

			total_len = ret;
			iov.iov_base = outbuf;
			iov.iov_len = total_len;

			if (tun_dev->use_ipv6) {
				msg.msg_name = &tun_dev->remote_addr6;
				msg.msg_namelen = sizeof(tun_dev->remote_addr6);
			} else {
				msg.msg_name = &tun_dev->remote_addr;
				msg.msg_namelen = sizeof(tun_dev->remote_addr);
			}

			ret = kernel_sendmsg(tun_dev->udp_sock, &msg, &iov, 1,
					     iov.iov_len);
			if (ret < 0)
				pr_warn(LOG_PREFIX
					"%s: kernel_sendmsg failed: %d\n",
					__func__, ret);

			kfree(outbuf);
			dev_kfree_skb(skb);
		}
	}

	pr_info(LOG_PREFIX "%s: TX thread exiting for device %s\n", __func__,
		dev->name);
	dev_put(dev);
	return 0;
}
