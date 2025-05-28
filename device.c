// SPDX-License-Identifier: GPL-2.0
#include <net/ip_tunnels.h>

#include "device.h"
#include "receive.h"
#include "transmit.h"

static int cryptotun_open(struct net_device *dev)
{
	struct cryptotun_device *tun_dev = netdev_priv(dev);
	int ret;
	int family = tun_dev->use_ipv6 ? AF_INET6 : AF_INET;

	pr_info(LOG_PREFIX "%s: Opening device %s\n", __func__, dev->name);

	pr_info(LOG_PREFIX "%s: Initializing socket (IPv6=%d)\n", __func__,
		tun_dev->use_ipv6);

	ret = sock_create_kern(&init_net, family, SOCK_DGRAM, IPPROTO_UDP,
			       &tun_dev->udp_sock);
	if (ret < 0)
		return ret;

	if (tun_dev->use_ipv6) {
		struct sockaddr_in6 addr6 = {
			.sin6_family = AF_INET6,
			.sin6_port = tun_dev->local_port,
			.sin6_addr = in6addr_any,
		};
		ret = tun_dev->udp_sock->ops->bind(tun_dev->udp_sock,
						   (struct sockaddr *)&addr6,
						   sizeof(addr6));
	} else {
		struct sockaddr_in addr4 = {
			.sin_family = AF_INET,
			.sin_port = tun_dev->local_port,
			.sin_addr.s_addr = htonl(INADDR_ANY),
		};
		ret = tun_dev->udp_sock->ops->bind(tun_dev->udp_sock,
						   (struct sockaddr *)&addr4,
						   sizeof(addr4));
	}

	if (ret < 0) {
		pr_err(LOG_PREFIX "%s: bind failed (%d)\n", __func__, ret);
		sock_release(tun_dev->udp_sock);
		tun_dev->udp_sock = NULL;
		return ret;
	}

	dev_hold(dev);
	tun_dev->rx_thread =
		kthread_run(cryptotun_rx_thread, dev, "cryptotun_rx_thread");
	if (IS_ERR(tun_dev->rx_thread)) {
		pr_err(LOG_PREFIX "%s: Failed to start RX thread\n", __func__);
		sock_release(tun_dev->udp_sock);
		tun_dev->udp_sock = NULL;
		return PTR_ERR(tun_dev->rx_thread);
	}

	init_waitqueue_head(&tun_dev->tx_wq);
	skb_queue_head_init(&tun_dev->tx_queue);

	dev_hold(dev);
	tun_dev->tx_thread =
		kthread_run(cryptotun_tx_thread, dev, "cryptotun_tx_thread");
	if (IS_ERR(tun_dev->tx_thread)) {
		pr_err(LOG_PREFIX "Failed to start TX thread\n");
		kthread_stop(tun_dev->rx_thread);
		sock_release(tun_dev->udp_sock);
		tun_dev->udp_sock = NULL;
		return PTR_ERR(tun_dev->tx_thread);
	}

	netif_start_queue(dev);
	netif_carrier_on(dev);

	return 0;
}

static int cryptotun_stop(struct net_device *dev)
{
	struct cryptotun_device *tun_dev = netdev_priv(dev);

	pr_info(LOG_PREFIX "%s: Stopping device %s\n", __func__, dev->name);

	netif_stop_queue(dev);

	if (tun_dev->rx_thread) {
		kthread_stop(tun_dev->rx_thread);
		tun_dev->rx_thread = NULL;
	}

	if (tun_dev->tx_thread) {
		kthread_stop(tun_dev->tx_thread);
		tun_dev->tx_thread = NULL;
	}
	skb_queue_purge(&tun_dev->tx_queue);

	if (tun_dev->udp_sock) {
		kernel_sock_shutdown(tun_dev->udp_sock, SHUT_RDWR);
		sock_release(tun_dev->udp_sock);
		tun_dev->udp_sock = NULL;
	}

	if (tun_dev->tx_aead) {
		crypto_free_aead(tun_dev->tx_aead);
		tun_dev->tx_aead = NULL;
	}

	if (tun_dev->rx_aead) {
		crypto_free_aead(tun_dev->rx_aead);
		tun_dev->rx_aead = NULL;
	}

	return 0;
}

static netdev_tx_t cryptotun_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct cryptotun_device *tun_dev = netdev_priv(dev);

	skb_queue_tail(&tun_dev->tx_queue, skb);
	wake_up_interruptible(&tun_dev->tx_wq);

	return NETDEV_TX_OK;
}

static const struct net_device_ops cryptotun_netdev_ops = {
	.ndo_open = cryptotun_open,
	.ndo_stop = cryptotun_stop,
	.ndo_start_xmit = cryptotun_xmit,
};

void cryptotun_setup(struct net_device *dev)
{
	struct cryptotun_device *tun_dev = netdev_priv(dev);

	memset(tun_dev, 0, sizeof(*tun_dev));
	spin_lock_init(&tun_dev->tx_counter_lock);
	tun_dev->nonce_prefix = (u32)ktime_get_real_seconds();

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
