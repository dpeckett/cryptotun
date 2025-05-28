// SPDX-License-Identifier: GPL-2.0
#include <linux/inet.h>

#include "crypto.h"
#include "device.h"
#include "netlink.h"

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

static int cryptotun_validate(struct nlattr *tb[], struct nlattr *data[],
			      struct netlink_ext_ack *extack)
{
	return 0;
}

static int cryptotun_newlink(struct net *net, struct net_device *dev,
			     struct nlattr *tb[], struct nlattr *data[],
			     struct netlink_ext_ack *extack)
{
	struct cryptotun_device *tun_dev = netdev_priv(dev);
	u8 key[KEY_LEN];
	int ret;

	pr_info(LOG_PREFIX "%s: creating new link\n", __func__);

	if (data[CRYPTOTUN_ATTR_LOCAL_PORT])
		tun_dev->local_port =
			htons(nla_get_u16(data[CRYPTOTUN_ATTR_LOCAL_PORT]));

	if (data[CRYPTOTUN_ATTR_REMOTE_PORT] &&
	    data[CRYPTOTUN_ATTR_REMOTE_IP]) {
		const char *ip_str = nla_data(data[CRYPTOTUN_ATTR_REMOTE_IP]);
		__be16 remote_port =
			htons(nla_get_u16(data[CRYPTOTUN_ATTR_REMOTE_PORT]));
		u8 ip4_buf[4];

		if (in4_pton(ip_str, -1, ip4_buf, -1, NULL)) {
			tun_dev->use_ipv6 = false;
			memset(&tun_dev->remote_addr, 0,
			       sizeof(tun_dev->remote_addr));
			tun_dev->remote_addr.sin_family = AF_INET;
			tun_dev->remote_addr.sin_port = remote_port;
			memcpy(&tun_dev->remote_addr.sin_addr.s_addr, ip4_buf,
			       4);
		} else if (in6_pton(ip_str, -1,
				    (u8 *)&tun_dev->remote_addr6.sin6_addr, -1,
				    NULL)) {
			tun_dev->use_ipv6 = true;
			memset(&tun_dev->remote_addr6, 0,
			       sizeof(tun_dev->remote_addr6));
			tun_dev->remote_addr6.sin6_family = AF_INET6;
			tun_dev->remote_addr6.sin6_port = remote_port;
		} else {
			pr_err(LOG_PREFIX "%s: invalid IP format\n", __func__);
			return -EINVAL;
		}
	} else {
		pr_err(LOG_PREFIX
		       "%s: Both remote IP and port must be provided\n",
		       __func__);
		return -EINVAL;
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
	tun_dev->tx_aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tun_dev->tx_aead))
		return PTR_ERR(tun_dev->tx_aead);

	if (crypto_aead_setkey(tun_dev->tx_aead, key, KEY_LEN) ||
	    crypto_aead_setauthsize(tun_dev->tx_aead, TAG_LEN)) {
		crypto_free_aead(tun_dev->tx_aead);
		tun_dev->tx_aead = NULL;
		return -EINVAL;
	}

	memcpy(key, nla_data(data[CRYPTOTUN_ATTR_RX_KEY]), KEY_LEN);
	tun_dev->rx_aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tun_dev->rx_aead)) {
		crypto_free_aead(tun_dev->tx_aead);
		tun_dev->tx_aead = NULL;
		return PTR_ERR(tun_dev->rx_aead);
	}

	if (crypto_aead_setkey(tun_dev->rx_aead, key, KEY_LEN) ||
	    crypto_aead_setauthsize(tun_dev->rx_aead, TAG_LEN)) {
		crypto_free_aead(tun_dev->tx_aead);
		crypto_free_aead(tun_dev->rx_aead);
		tun_dev->tx_aead = NULL;
		tun_dev->rx_aead = NULL;
		return -EINVAL;
	}

	ret = register_netdevice(dev);
	return ret;
}

struct rtnl_link_ops cryptotun_link_ops = {
	.kind = "cryptotun",
	.setup = cryptotun_setup,
	.priv_size = sizeof(struct cryptotun_device),
	.validate = cryptotun_validate,
	.newlink = cryptotun_newlink,
	.policy = cryptotun_policy,
	.maxtype = CRYPTOTUN_ATTR_MAX,
};
