// SPDX-License-Identifier: GPL-2.0
#include <crypto/aead.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/etherdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/random.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/udp.h>
#include <net/ip_tunnels.h>
#include <net/rtnetlink.h>
#include <net/sock.h>

#define BUF_SIZE 2000
#define LOG_PREFIX "[cryptotun] "
#define KEY_LEN 16
#define TAG_LEN 16
#define NONCE_LEN 12

enum cryptotun_attrs {
	CRYPTOTUN_ATTR_UNSPEC,
	CRYPTOTUN_ATTR_LOCAL_PORT,
	CRYPTOTUN_ATTR_REMOTE_PORT,
	CRYPTOTUN_ATTR_REMOTE_IP,
	CRYPTOTUN_ATTR_TX_KEY,
	CRYPTOTUN_ATTR_RX_KEY,
	__CRYPTOTUN_ATTR_MAX,
};

#define CRYPTOTUN_ATTR_MAX (__CRYPTOTUN_ATTR_MAX - 1)

static const struct nla_policy cryptotun_policy[CRYPTOTUN_ATTR_MAX + 1] = {
	[CRYPTOTUN_ATTR_LOCAL_PORT] = { .type = NLA_U16 },
	[CRYPTOTUN_ATTR_REMOTE_PORT] = { .type = NLA_U16 },
	[CRYPTOTUN_ATTR_REMOTE_IP] = { .type = NLA_STRING,
				       .len = INET6_ADDRSTRLEN },
	[CRYPTOTUN_ATTR_TX_KEY] = { .type = NLA_BINARY, .len = KEY_LEN },
	[CRYPTOTUN_ATTR_RX_KEY] = { .type = NLA_BINARY, .len = KEY_LEN },
};

struct cryptotun_header {
	__be64 nonce;
} __packed;

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
};

static int cryptotun_rx_thread(void *data);

static void generate_iv(u64 nonce, u8 *iv)
{
	memset(iv, 0, NONCE_LEN);
	memcpy(iv + 4, &nonce, sizeof(nonce));
}

static int cryptotun_tx_thread(void *data)
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

static netdev_tx_t cryptotun_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct cryptotun_priv *priv = netdev_priv(dev);

	skb_queue_tail(&priv->tx_queue, skb);
	wake_up_interruptible(&priv->tx_wq);

	return NETDEV_TX_OK;
}

static int cryptotun_rx_thread(void *data)
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

			pr_debug(LOG_PREFIX "%s: decrypting nonce=%llu\n",
				 __func__,
				 (unsigned long long)be64_to_cpu(hdr->nonce));

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

static int udp_socket_init(struct net_device *dev)
{
	struct cryptotun_priv *priv = netdev_priv(dev);
	int ret;
	int family = priv->use_ipv6 ? AF_INET6 : AF_INET;

	pr_info(LOG_PREFIX "%s: Initializing socket (IPv6=%d)\n", __func__,
		priv->use_ipv6);

	ret = sock_create_kern(&init_net, family, SOCK_DGRAM, IPPROTO_UDP,
			       &priv->udp_sock);
	if (ret < 0)
		return ret;

	if (priv->use_ipv6) {
		struct sockaddr_in6 addr6 = {
			.sin6_family = AF_INET6,
			.sin6_port = priv->local_port,
			.sin6_addr = in6addr_any,
		};
		ret = priv->udp_sock->ops->bind(priv->udp_sock,
						(struct sockaddr *)&addr6,
						sizeof(addr6));
	} else {
		struct sockaddr_in addr4 = {
			.sin_family = AF_INET,
			.sin_port = priv->local_port,
			.sin_addr.s_addr = htonl(INADDR_ANY),
		};
		ret = priv->udp_sock->ops->bind(priv->udp_sock,
						(struct sockaddr *)&addr4,
						sizeof(addr4));
	}

	if (ret < 0) {
		pr_err(LOG_PREFIX "%s: bind failed (%d)\n", __func__, ret);
		sock_release(priv->udp_sock);
		priv->udp_sock = NULL;
	}

	return ret;
}

static int cryptotun_open(struct net_device *dev)
{
	struct cryptotun_priv *priv = netdev_priv(dev);
	int ret;

	pr_info(LOG_PREFIX "%s: Opening device %s\n", __func__, dev->name);

	ret = udp_socket_init(dev);
	if (ret < 0)
		return ret;

	dev_hold(dev);
	priv->rx_thread =
		kthread_run(cryptotun_rx_thread, dev, "cryptotun_rx_thread");
	if (IS_ERR(priv->rx_thread)) {
		pr_err(LOG_PREFIX "%s: Failed to start RX thread\n", __func__);
		sock_release(priv->udp_sock);
		priv->udp_sock = NULL;
		return PTR_ERR(priv->rx_thread);
	}

	init_waitqueue_head(&priv->tx_wq);
	skb_queue_head_init(&priv->tx_queue);

	dev_hold(dev);
	priv->tx_thread =
		kthread_run(cryptotun_tx_thread, dev, "cryptotun_tx_thread");
	if (IS_ERR(priv->tx_thread)) {
		pr_err(LOG_PREFIX "Failed to start TX thread\n");
		kthread_stop(priv->rx_thread);
		sock_release(priv->udp_sock);
		priv->udp_sock = NULL;
		return PTR_ERR(priv->tx_thread);
	}

	netif_start_queue(dev);
	netif_carrier_on(dev);

	return 0;
}

static int cryptotun_stop(struct net_device *dev)
{
	struct cryptotun_priv *priv = netdev_priv(dev);

	pr_info(LOG_PREFIX "%s: Stopping device %s\n", __func__, dev->name);

	netif_stop_queue(dev);

	if (priv->rx_thread) {
		kthread_stop(priv->rx_thread);
		priv->rx_thread = NULL;
	}

	if (priv->tx_thread) {
		kthread_stop(priv->tx_thread);
		priv->tx_thread = NULL;
	}
	skb_queue_purge(&priv->tx_queue);

	if (priv->udp_sock) {
		kernel_sock_shutdown(priv->udp_sock, SHUT_RDWR);
		sock_release(priv->udp_sock);
		priv->udp_sock = NULL;
	}

	if (priv->tx_aead) {
		crypto_free_aead(priv->tx_aead);
		priv->tx_aead = NULL;
	}

	if (priv->rx_aead) {
		crypto_free_aead(priv->rx_aead);
		priv->rx_aead = NULL;
	}

	return 0;
}

static const struct net_device_ops cryptotun_netdev_ops = {
	.ndo_open = cryptotun_open,
	.ndo_stop = cryptotun_stop,
	.ndo_start_xmit = cryptotun_xmit,
};

static void cryptotun_setup(struct net_device *dev)
{
	struct cryptotun_priv *priv = netdev_priv(dev);

	memset(priv, 0, sizeof(*priv));
	spin_lock_init(&priv->nonce_lock);
	priv->nonce_prefix = (u32)ktime_get_real_seconds();

	dev->netdev_ops = &cryptotun_netdev_ops;
	dev->header_ops = &ip_tunnel_header_ops; // Layer 3 interface
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->type = ARPHRD_NONE;
	dev->flags = IFF_NOARP | IFF_POINTOPOINT;
	dev->priv_flags |= IFF_NO_QUEUE;
	dev->features = 0;
	//dev->features |= NETIF_F_LLTX;
	dev->mtu = 1280;

	pr_info(LOG_PREFIX "%s: device setup completed\n", __func__);
}

static int cryptotun_validate(struct nlattr *tb[], struct nlattr *data[],
			      struct netlink_ext_ack *extack)
{
	return 0;
}

static int cryptotun_newlink(struct net *net, struct net_device *dev,
			     struct nlattr *tb[], struct nlattr *data[],
			     struct netlink_ext_ack *extack)
{
	struct cryptotun_priv *priv = netdev_priv(dev);
	u8 key[KEY_LEN];
	int ret;

	pr_info(LOG_PREFIX "%s: creating new link\n", __func__);

	if (data[CRYPTOTUN_ATTR_LOCAL_PORT])
		priv->local_port =
			htons(nla_get_u16(data[CRYPTOTUN_ATTR_LOCAL_PORT]));

	if (data[CRYPTOTUN_ATTR_REMOTE_PORT])
		priv->remote_port =
			htons(nla_get_u16(data[CRYPTOTUN_ATTR_REMOTE_PORT]));

	if (data[CRYPTOTUN_ATTR_REMOTE_IP]) {
		const char *ip_str = nla_data(data[CRYPTOTUN_ATTR_REMOTE_IP]);
		u8 ip4_buf[4];

		pr_debug(LOG_PREFIX "%s: parsing remote IP: %s\n", __func__,
			 ip_str);

		if (in4_pton(ip_str, -1, ip4_buf, -1, NULL)) {
			priv->remote_ip4 = *(__be32 *)ip4_buf;
			priv->use_ipv6 = false;
			pr_debug(LOG_PREFIX "%s: remote is IPv4\n", __func__);
		} else if (in6_pton(ip_str, -1, (u8 *)&priv->remote_ip6, -1,
				    NULL)) {
			priv->use_ipv6 = true;
			pr_debug(LOG_PREFIX "%s: remote is IPv6\n", __func__);
		} else {
			pr_err(LOG_PREFIX "%s: invalid IP format\n", __func__);
			return -EINVAL;
		}
	}

	if (!data[CRYPTOTUN_ATTR_TX_KEY] || !data[CRYPTOTUN_ATTR_RX_KEY]) {
		pr_err(LOG_PREFIX
		       "%s: Both TX and RX keys must be configured\n",
		       __func__);
		return -EINVAL;
	}

	if (nla_len(data[CRYPTOTUN_ATTR_TX_KEY]) != KEY_LEN ||
	    nla_len(data[CRYPTOTUN_ATTR_RX_KEY]) != KEY_LEN) {
		pr_err(LOG_PREFIX "%s: Invalid key length\n", __func__);
		return -EINVAL;
	}

	memcpy(key, nla_data(data[CRYPTOTUN_ATTR_TX_KEY]), KEY_LEN);
	priv->tx_aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(priv->tx_aead)) {
		pr_err(LOG_PREFIX "%s: failed to allocate TX AEAD\n", __func__);
		return PTR_ERR(priv->tx_aead);
	}
	if (crypto_aead_setkey(priv->tx_aead, key, KEY_LEN) ||
	    crypto_aead_setauthsize(priv->tx_aead, TAG_LEN)) {
		crypto_free_aead(priv->tx_aead);
		priv->tx_aead = NULL;
		return -EINVAL;
	}

	memcpy(key, nla_data(data[CRYPTOTUN_ATTR_RX_KEY]), KEY_LEN);
	priv->rx_aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(priv->rx_aead)) {
		pr_err(LOG_PREFIX "%s: failed to allocate RX AEAD\n", __func__);
		crypto_free_aead(priv->tx_aead);
		priv->tx_aead = NULL;
		return PTR_ERR(priv->rx_aead);
	}
	if (crypto_aead_setkey(priv->rx_aead, key, KEY_LEN) ||
	    crypto_aead_setauthsize(priv->rx_aead, TAG_LEN)) {
		crypto_free_aead(priv->tx_aead);
		crypto_free_aead(priv->rx_aead);
		priv->tx_aead = NULL;
		priv->rx_aead = NULL;
		return -EINVAL;
	}

	ret = register_netdevice(dev);
	if (ret == 0)
		pr_info(LOG_PREFIX "%s: device registered successfully\n",
			__func__);
	else
		pr_err(LOG_PREFIX "%s: device registration failed (%d)\n",
		       __func__, ret);

	return ret;
}

static struct rtnl_link_ops cryptotun_link_ops = {
	.kind = "cryptotun",
	.setup = cryptotun_setup,
	.priv_size = sizeof(struct cryptotun_priv),
	.validate = cryptotun_validate,
	.newlink = cryptotun_newlink,
	.policy = cryptotun_policy,
	.maxtype = CRYPTOTUN_ATTR_MAX,
};

static int __init cryptotun_init(void)
{
	pr_info(LOG_PREFIX "%s: loading module\n", __func__);
	return rtnl_link_register(&cryptotun_link_ops);
}

static void __exit cryptotun_exit(void)
{
	pr_info(LOG_PREFIX "%s: unloading module\n", __func__);
	rtnl_link_unregister(&cryptotun_link_ops);
}

module_init(cryptotun_init);
module_exit(cryptotun_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Damian Peckett <damian@pecke.tt>");
MODULE_DESCRIPTION("Cryptotun - A minimal secure tunneling device");
