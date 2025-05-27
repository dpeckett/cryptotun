// SPDX-License-Identifier: GPL-2.0
#include "device.h"
#include "netlink.h"

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
