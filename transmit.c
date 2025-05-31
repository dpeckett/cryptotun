// SPDX-License-Identifier: GPL-2.0
#include "transmit.h"
#include "crypto.h"
#include "device.h"
#include "messages.h"

void cryptotun_tx_work_handler(struct work_struct *work)
{
	struct cryptotun_device *tun_dev =
		container_of(work, struct cryptotun_device, tx_work.work);
	struct msghdr msg = {};
	struct kvec iov;
	unsigned int out_len;
	u8 *out = NULL;
	int ret;

	while (!skb_queue_empty(&tun_dev->tx_queue)) {
		struct sk_buff *skb = skb_dequeue(&tun_dev->tx_queue);

		out_len = sizeof(struct cryptotun_header) + skb->len + TAG_LEN;
		out = netdev_alloc_frag(out_len);
		if (!out) {
			pr_warn(LOG_PREFIX
				"%s: Failed to allocate output buffer\n",
				__func__);
			continue;
		}

		ret = cryptotun_encrypt_packet(tun_dev, skb->data, skb->len,
					       out, out_len);

		dev_kfree_skb(skb);

		if (ret < 0) {
			pr_warn(LOG_PREFIX "%s: Encryption failed (%d)\n",
				__func__, ret);
			skb_free_frag(out);
			continue;
		}

		iov.iov_base = out;
		iov.iov_len = out_len;

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
			pr_warn(LOG_PREFIX "%s: kernel_sendmsg failed: %d\n",
				__func__, ret);

		skb_free_frag(out);
	}
}
