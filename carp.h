/*
 * 	carp.h
 *
 * 2004 Copyright (c) Evgeniy Polyakov <johnpol@2ka.mipt.ru>
 * 2012 Copyright (c) Damien Churchill <damoxc@gmail.com>
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

#ifndef __CARP_H
#define __CARP_H

#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/proc_fs.h>

#include "carp_ioctl.h"

#define DRV_VERSION     "0.0.2"
#define DRV_RELDATE     "March 21, 2012"
#define DRV_NAME        "carp"
#define DRV_DESCRIPTION "Common Address Redundancy Protocol Driver"
#define DRV_DESC DRV_DESCRIPTION ": v" DRV_VERSION " (" DRV_RELDATE ")\n"

#define IPPROTO_CARP           112
#define	CARP_VERSION             2
#define CARP_TTL               255
#define	CARP_SIG_LEN            20
#define CARP_DEFAULT_TX_QUEUES  16
#define CARP_STATE_LEN           8

#define MULTICAST(x)    (((x) & htonl(0xf0000000)) == htonl(0xe0000000))
#define MULTICAST_ADDR  addr2val(224, 0, 0, 18)

#define timeval_before(before, after)    		\
    (((before)->tv_sec == (after)->tv_sec) ? ((before)->tv_usec < (after)->tv_usec) : ((before)->tv_sec < (after)->tv_sec))


extern int carp_net_id;

/*
 * carp->flags definitions.
 */
#define CARP_DATA_AVAIL		(1<<0)

struct carp_header {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	u8	carp_type:4,
		carp_version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	u8	carp_version:4,
		carp_type:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	u8	carp_vhid;
	u8	carp_advskew;
	u8	carp_authlen;
	u8	carp_pad1;
	u8	carp_advbase;
	u16	carp_cksum;
	u32	carp_counter[2];
	u8	carp_md[CARP_SIG_LEN];
};

struct carp_stat {
	u32	crc_errors;
	u32	ver_errors;
	u32	vhid_errors;
	u32	hmac_errors;
	u32	counter_errors;

	u32	mem_errors;
	u32	xmit_errors;

	u32	bytes_sent;
};

struct carp_net {
    struct net            *net;
    struct list_head       dev_list;
    struct proc_dir_entry *proc_dir;
};

struct carp {
	struct net_device_stats stat;
	struct net_device      *dev, *odev;
	char                    name[IFNAMSIZ];

	int	                    link, mlink;
	struct iphdr            iph;

	u32                     md_timeout, adv_timeout;
	struct timer_list       md_timer, adv_timer;

	enum carp_state         state;
	struct carp_header      hdr;
	struct carp_stat        cstat;

	u8                      carp_key[CARP_KEY_LEN];
	u8                      carp_pad[CARP_HMAC_PAD_LEN];
	struct crypto_hash     *hash;

    u8                      hwaddr[ETH_ALEN];

	u64                     carp_adv_counter;

	spinlock_t              lock;

	u32                     flags;
	unsigned short          oflags;

    struct   proc_dir_entry *proc_entry;
    char     proc_file_name[IFNAMSIZ];

    struct   dentry *debug_dir;
};

static inline char *carp_state_fmt(struct carp *carp)
{
    switch (carp->state) {
        case MASTER:
            return "MASTER";
        case INIT:
            return "INIT";
        case BACKUP:
            return "BACKUP";
    }
    return NULL;
}

int carp_crypto_hmac(struct carp *, struct scatterlist *, u8 *);
void carp_set_state(struct carp *, enum carp_state);

// Implemented in carp_proto.c
int carp_register_protocol(void);
int carp_unregister_protocol(void);

// Implemented in carp_debugfs.c
void carp_create_debugfs(void);
void carp_destroy_debugfs(void);

// Implemented in carp_procfs.c
void carp_create_proc_entry(struct carp *carp);
void carp_remove_proc_entry(struct carp *carp);
void __net_init carp_create_proc_dir(struct carp_net *cn);
void __net_exit carp_destroy_proc_dir(struct carp_net *cn);

// Implemented in carp_sysfs.c
int carp_create_sysfs(struct carp_net *cn);
void carp_destroy_sysfs(struct carp_net *cn);

#endif /* __CARP_H */
