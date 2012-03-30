/*
 * 	carp_log.c
 *
 * 2004 Copyright (c) Evgeniy Polyakov <johnpol@xxxxxxxxxxx>
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/random.h>
#include <linux/crypto.h>

#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/arp.h>

#include <asm/scatterlist.h>
#include <asm/delay.h>

#include "carp.h"
#include "carp_log.h"

void dump_addr_info(struct carp *carp)
{
	int i;

    printk("carp: %s addr: hw=", carp->dev->name);
    if (carp->odev) {
        for (i=0; i<ETH_ALEN; ++i)
            printk("%02x%c", (unsigned char)carp->odev->dev_addr[i], (i==ETH_ALEN-1)?' ':':');
    } else {
        printk("n/a");
    }

	printk(", sw=");
	for (i=0; i<4; ++i)
		printk("%d%c", (ntohl(carp->iph.saddr) >> (3-i)*8)&0xff, (i==3)?' ':'.');
	printk(", dst=");
	for (i=0; i<4; ++i)
		printk("%d%c", (ntohl(carp->iph.daddr) >> (3-i)*8)&0xff, (i==3)?' ':'.');
	printk("\n");
}

void dump_hmac_params(struct carp *carp)
{
	int i;
	u8 carp_md[CARP_SIG_LEN];
	struct scatterlist sg;

    sg_set_buf(&sg, &carp->carp_adv_counter, sizeof(carp->carp_adv_counter));

    if (carp_crypto_hmac(carp, &sg, carp_md))
        return;

	printk(KERN_INFO "key: ");
	for (i=0; i<CARP_KEY_LEN; ++i)
		printk("%02x ", carp->carp_key[i]);
	printk("\n");

	printk("counter: %llx ", carp->carp_adv_counter);

	printk("hmac: ");
	for (i=0; i<CARP_SIG_LEN; ++i)
		printk("%02x ", carp_md[i]);
	printk("\n");
}

void dump_carp_header(struct carp_header *carp_hdr)
{
	u64 counter;
	int i;

	counter = ntohl(carp_hdr->carp_counter[0]);
	counter = counter<<32;
	counter += ntohl(carp_hdr->carp_counter[1]);

	carp_dbg("carp: type=%u, version=%u, vhid=%u, skew=%u, base=%u, counter=%llu, md={",
			carp_hdr->carp_type,
			carp_hdr->carp_version,
			carp_hdr->carp_vhid,
			carp_hdr->carp_advskew,
			carp_hdr->carp_advbase,
			counter);

	for (i=0; i<sizeof(carp_hdr->carp_md); ++i)
	{
		printk("%02x ", carp_hdr->carp_md[i]);
	}
	printk("}\n");
}

