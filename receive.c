// SPDX-License-Identifier: GPL-2.0
#include "crypto.h"
#include "device.h"
#include "messages.h"
#include "replay.h"

#define BUF_SIZE 2000

int cryptotun_rx_thread(void *data)
{
	struct net_device *dev = data;
	struct cryptotun_priv *priv = netdev_priv(dev);
	struct msghdr msg = {};
	struct kvec iov;
	struct sk_buff *skb;
	void *buf;
	int len;

	if (!priv->udp_sock) {
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
		len = kernel_recvmsg(priv->udp_sock, &msg, &iov, 1, BUF_SIZE,
				     MSG_DONTWAIT);
		if (len <= 0) {
			usleep_range(10000, 20000);
			continue;
		}

		pr_debug(LOG_PREFIX "%s: received packet length %d\n", __func__,
			 len);

		if (priv->rx_aead &&
		    len > sizeof(struct cryptotun_header) + TAG_LEN) {
			struct cryptotun_header *hdr = buf;
			u8 *cipher = buf + sizeof(*hdr);
			int cipher_len = len - sizeof(*hdr);
			u8 iv[NONCE_LEN];
			u8 *plain;
			struct scatterlist sg_in[2], sg_out[2];

			struct aead_request *req;

			plain = kmalloc(cipher_len - TAG_LEN, GFP_KERNEL);
			if (!plain)
				continue;

			generate_iv(be64_to_cpu(hdr->nonce), iv);

			sg_init_table(sg_in, 2);
			sg_set_buf(&sg_in[0], hdr, sizeof(*hdr));
			sg_set_buf(&sg_in[1], cipher, cipher_len);

			sg_init_table(sg_out, 2);
			sg_set_buf(&sg_out[0], hdr, sizeof(*hdr));
			sg_set_buf(&sg_out[1], plain, cipher_len - TAG_LEN);

			req = aead_request_alloc(priv->rx_aead, GFP_KERNEL);
			if (!req) {
				memzero_explicit(plain, cipher_len - TAG_LEN);
				kfree(plain);
				continue;
			}

			aead_request_set_callback(req, 0, NULL, NULL);
			aead_request_set_crypt(req, sg_in, sg_out, cipher_len,
					       iv);
			aead_request_set_ad(req, sizeof(*hdr));

			if (crypto_aead_decrypt(req)) {
				pr_warn(LOG_PREFIX
					"%s: AEAD decryption failed\n",
					__func__);
				aead_request_free(req);
				memzero_explicit(plain, cipher_len - TAG_LEN);
				kfree(plain);
				continue;
			}

			aead_request_free(req);

			// Is it a known message type?
			if (be32_to_cpu(hdr->type) != CRYPTOTUN_MSG_TYPE_DATA) {
				pr_warn(LOG_PREFIX
					"%s: unknown message type %u, dropping packet\n",
					__func__, be32_to_cpu(hdr->type));
				memzero_explicit(plain, cipher_len - TAG_LEN);
				kfree(plain);
				continue;
			}

			// Confirm the packet has not been replayed
			if (!cryptotun_replay_counter_validate(
				    &priv->replay_counter,
				    be64_to_cpu(hdr->nonce))) {
				pr_warn(LOG_PREFIX
					"%s: packet is a replay, dropping\n",
					__func__);
				memzero_explicit(plain, cipher_len - TAG_LEN);
				kfree(plain);
				continue;
			}

			skb = alloc_skb(cipher_len - TAG_LEN + NET_IP_ALIGN,
					GFP_KERNEL);
			if (!skb) {
				memzero_explicit(plain, cipher_len - TAG_LEN);
				kfree(plain);
				continue;
			}

			skb_reserve(skb, NET_IP_ALIGN);
			memcpy(skb_put(skb, cipher_len - TAG_LEN), plain,
			       cipher_len - TAG_LEN);
			memzero_explicit(plain, cipher_len - TAG_LEN);
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
