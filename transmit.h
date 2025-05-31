/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _CRYPTOTUN_TRANSMIT_H
#define _CRYPTOTUN_TRANSMIT_H

#include <linux/workqueue.h>

void cryptotun_tx_work_handler(struct work_struct *work);

#endif /* _CRYPTOTUN_TRANSMIT_H */
