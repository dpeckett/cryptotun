// SPDX-License-Identifier: GPL-2.0
#include "crypto.h"
#include "device.h"
#include "messages.h"

int cryptotun_tx_thread(void *data)
{
	struct net_device *dev = data;
	struct cryptotun_priv *priv = netdev_priv(dev);

	struct sockaddr_in6 daddr6;
	struct sockaddr_in daddr4;

	memset(&daddr6, 0, sizeof(daddr6));
	memset(&daddr4, 0, sizeof(daddr4));

	if (priv->use_ipv6) {
		daddr6.sin6_family = AF_INET6;
		daddr6.sin6_port = priv->remote_port;
		daddr6.sin6_addr = priv->remote_ip6;
	} else {
		daddr4.sin_family = AF_INET;
		daddr4.sin_port = priv->remote_port;
		daddr4.sin_addr.s_addr = priv->remote_ip4;
	}

	pr_info(LOG_PREFIX "%s: TX thread started for device %s\n", __func__,
		dev->name);

	while (!kthread_should_stop()) {
		wait_event_interruptible(priv->tx_wq,
					 !skb_queue_empty(&priv->tx_queue) ||
						 kthread_should_stop());

		while (!skb_queue_empty(&priv->tx_queue)) {
			struct sk_buff *skb = skb_dequeue(&priv->tx_queue);
			struct aead_request *req = NULL;
			struct scatterlist sg_in[2], sg_out[2];
			struct msghdr msg = {};
			struct kvec iov;
			struct cryptotun_header *hdr = NULL;
			u8 *inbuf = NULL, *outbuf = NULL;
			u8 iv[NONCE_LEN];
			int data_len = skb->len;
			int out_len = data_len + TAG_LEN;
			int total_len =
				sizeof(struct cryptotun_header) + out_len;
			int len;

			inbuf = kmemdup(skb->data, data_len, GFP_KERNEL);
			if (!inbuf) {
				dev_kfree_skb(skb);
				continue;
			}

			outbuf = kmalloc(total_len, GFP_KERNEL);
			if (!outbuf) {
				kfree(inbuf);
				dev_kfree_skb(skb);
				continue;
			}

			hdr = (struct cryptotun_header *)outbuf;
			spin_lock(&priv->nonce_lock);
			hdr->nonce =
				cpu_to_be64(((u64)priv->nonce_prefix << 32) |
					    priv->nonce_counter++);
			spin_unlock(&priv->nonce_lock);

			generate_iv(be64_to_cpu(hdr->nonce), iv);

			req = aead_request_alloc(priv->tx_aead, GFP_KERNEL);
			if (!req) {
				pr_warn(LOG_PREFIX
					"%s: aead_request_alloc failed\n",
					__func__);
				kfree(inbuf);
				kfree(outbuf);
				dev_kfree_skb(skb);
				continue;
			}

			sg_init_table(sg_in, 2);
			sg_set_buf(&sg_in[0], hdr, sizeof(*hdr));
			sg_set_buf(&sg_in[1], inbuf, data_len);

			sg_init_table(sg_out, 2);
			sg_set_buf(&sg_out[0], hdr, sizeof(*hdr));
			sg_set_buf(&sg_out[1], outbuf + sizeof(*hdr), out_len);

			aead_request_set_callback(req, 0, NULL, NULL);
			aead_request_set_crypt(req, sg_in, sg_out, data_len,
					       iv);
			aead_request_set_ad(req, sizeof(*hdr));

			if (crypto_aead_encrypt(req)) {
				pr_warn(LOG_PREFIX
					"%s: AEAD encryption failed\n",
					__func__);
				aead_request_free(req);
				kfree(inbuf);
				kfree(outbuf);
				dev_kfree_skb(skb);
				continue;
			}

			aead_request_free(req);
			kfree(inbuf);

			iov.iov_base = outbuf;
			iov.iov_len = total_len;

			if (priv->use_ipv6) {
				msg.msg_name = &daddr6;
				msg.msg_namelen = sizeof(daddr6);
			} else {
				msg.msg_name = &daddr4;
				msg.msg_namelen = sizeof(daddr4);
			}

			len = kernel_sendmsg(priv->udp_sock, &msg, &iov, 1,
					     iov.iov_len);
			if (len < 0)
				pr_warn(LOG_PREFIX
					"%s: kernel_sendmsg failed: %d\n",
					__func__, len);

			kfree(outbuf);
			dev_kfree_skb(skb);
		}
	}

	pr_info(LOG_PREFIX "%s: TX thread exiting for device %s\n", __func__,
		dev->name);
	dev_put(dev);
	return 0;
}
