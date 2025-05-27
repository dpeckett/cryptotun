// SPDX-License-Identifier: GPL-2.0
#include <net/ip_tunnels.h>

#include "device.h"
#include "receive.h"
#include "transmit.h"

static int cryptotun_open(struct net_device *dev)
{
	struct cryptotun_priv *priv = netdev_priv(dev);
	int ret;
	int family = priv->use_ipv6 ? AF_INET6 : AF_INET;

	pr_info(LOG_PREFIX "%s: Opening device %s\n", __func__, dev->name);

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
		return ret;
	}

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

static netdev_tx_t cryptotun_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct cryptotun_priv *priv = netdev_priv(dev);

	skb_queue_tail(&priv->tx_queue, skb);
	wake_up_interruptible(&priv->tx_wq);

	return NETDEV_TX_OK;
}

static const struct net_device_ops cryptotun_netdev_ops = {
	.ndo_open = cryptotun_open,
	.ndo_stop = cryptotun_stop,
	.ndo_start_xmit = cryptotun_xmit,
};

void cryptotun_setup(struct net_device *dev)
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
	dev->mtu = 1280;

	pr_info(LOG_PREFIX "%s: device setup completed\n", __func__);
}
