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

		if (in4_pton(ip_str, -1, ip4_buf, -1, NULL)) {
			priv->remote_ip4 = *(__be32 *)ip4_buf;
			priv->use_ipv6 = false;
		} else if (in6_pton(ip_str, -1, (u8 *)&priv->remote_ip6, -1,
				    NULL)) {
			priv->use_ipv6 = true;
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
	if (IS_ERR(priv->tx_aead))
		return PTR_ERR(priv->tx_aead);

	if (crypto_aead_setkey(priv->tx_aead, key, KEY_LEN) ||
	    crypto_aead_setauthsize(priv->tx_aead, TAG_LEN)) {
		crypto_free_aead(priv->tx_aead);
		priv->tx_aead = NULL;
		return -EINVAL;
	}

	memcpy(key, nla_data(data[CRYPTOTUN_ATTR_RX_KEY]), KEY_LEN);
	priv->rx_aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(priv->rx_aead)) {
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
	return ret;
}

struct rtnl_link_ops cryptotun_link_ops = {
	.kind = "cryptotun",
	.setup = cryptotun_setup,
	.priv_size = sizeof(struct cryptotun_priv),
	.validate = cryptotun_validate,
	.newlink = cryptotun_newlink,
	.policy = cryptotun_policy,
	.maxtype = CRYPTOTUN_ATTR_MAX,
};
