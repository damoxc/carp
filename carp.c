/*
 * 	carp.c
 *
 * 2004 Copyright (c) Evgeniy Polyakov <johnpol@2ka.mipt.ru>
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
#include <asm/uaccess.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/in.h>
#include <linux/in_route.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include <linux/mroute.h>
#include <linux/init.h>
#include <linux/in6.h>
#include <linux/inetdevice.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/crypto.h>
#include <linux/random.h>

#include <net/route.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/protocol.h>
#include <net/arp.h>
#include <net/checksum.h>
#include <net/inet_ecn.h>

#include <asm/scatterlist.h>

#ifdef CONFIG_IPV6
#include <net/ipv6.h>
#include <net/ip6_fib.h>
#include <net/ip6_route.h>
#endif

#include "carp.h"
#include "carp_log.h"
#include "carp_queue.h"
#include "carp_ioctl.h"

#define timeval_before(before, after)			\
	(((before)->tv_sec == (after)->tv_sec) ? ((before)->tv_usec < (after)->tv_usec) : ((before)->tv_sec < (after)->tv_sec))


static int carp_init(struct net_device *);
static void carp_uninit(struct net_device *);
static void carp_setup(struct net_device *);
static int carp_close(struct net_device *);
static int carp_open(struct net_device *);
static int carp_ioctl (struct net_device *, struct ifreq *, int);
static int carp_check_params(struct carp_ioctl_params);

static void carp_err(struct sk_buff *, u32);
static int carp_rcv(struct sk_buff *);
static int carp_xmit(struct sk_buff *, struct net_device *);

static struct net_device_stats *carp_get_stats(struct net_device *);

static void carp_hmac_sign(struct carp_priv *, struct carp_header *);
static int carp_hmac_verify(struct carp_priv *, struct carp_header *);
static u32 inline addr2val(u8, u8, u8, u8);

static void carp_set_state(struct carp_priv *, enum carp_state);
static void carp_master_down(unsigned long);
static void carp_advertise(unsigned long);

static int __init device_carp_init(void);
void __exit device_carp_fini(void);

static struct net_device *carp_dev;

static void carp_uninit(struct net_device *dev)
{
	struct carp_priv *cp = netdev_priv(dev);

	if (timer_pending(&cp->md_timer))
		del_timer_sync(&cp->md_timer);
	if (timer_pending(&cp->adv_timer))
		del_timer_sync(&cp->adv_timer);

	log("%s\n", __func__);
	dev_put(cp->odev);
	dev_put(dev);
}

static void carp_err(struct sk_buff *skb, u32 info)
{
	log("%s\n", __func__);
	kfree_skb(skb);
}

static void carp_hmac_sign(struct carp_priv *cp, struct carp_header *ch)
{
	unsigned int keylen = sizeof(cp->carp_key);
	struct scatterlist sg;
    struct hash_desc desc;

    sg_assign_page(&sg, virt_to_page(ch->carp_counter));
	sg.offset = ((unsigned long)(ch->carp_counter)) % PAGE_SIZE;
	sg.length = sizeof(ch->carp_counter);

    desc.tfm = cp->tfm;
    desc.flags = 0;

    if (crypto_hash_setkey(desc.tfm, cp->carp_key, keylen) ||
        crypto_hash_digest(&desc, &sg, sg.length, ch->carp_md)) {
    }

	//crypto_hmac(cp->tfm, cp->carp_key, &keylen, &sg, 1, ch->carp_md);
}

static int carp_hmac_verify(struct carp_priv *cp, struct carp_header *ch)
{
	u8 tmp_md[CARP_SIG_LEN];
	unsigned int keylen = sizeof(cp->carp_key);
	struct scatterlist sg;
    struct hash_desc desc;

	sg_assign_page(&sg, virt_to_page(ch->carp_counter));
	sg.offset = ((unsigned long)(ch->carp_counter)) % PAGE_SIZE;
	sg.length = sizeof(ch->carp_counter);

    desc.tfm = cp->tfm;
    desc.flags = 0;


    if (crypto_hash_setkey(desc.tfm, cp->carp_key, keylen) ||
        crypto_hash_digest(&desc, &sg, sg.length, ch->carp_md)) {
    }

	//crypto_hmac(cp->tfm, cp->carp_key, &keylen, &sg, 1, tmp_md);
#if 0
	{
		int i;
		printk("calculated:  ");
		for (i=0; i<CARP_SIG_LEN; ++i)
			printk("%02x ", tmp_md[i]);
		printk("\n");
		printk("from header: ");
		for (i=0; i<CARP_SIG_LEN; ++i)
			printk("%02x ", ch->carp_md[i]);
		printk("\n");
	}
#endif
	return memcmp(tmp_md, ch->carp_md, CARP_SIG_LEN);
}

static int carp_check_params(struct carp_ioctl_params p)
{
	if (p.state != INIT && p.state != BACKUP && p.state != MASTER)
	{
		log("Wrong state %d.\n", p.state);
		return -1;
	}

	if (!__dev_get_by_name(dev_net(carp_dev), p.devname))
	{
		log("No such device %s.\n", p.devname);
		return -2;
	}

	if (p.md_timeout > MAX_MD_TIMEOUT || p.adv_timeout > MAX_ADV_TIMEOUT ||
	    !p.md_timeout || !p.adv_timeout)
		return -3;

	return 0;
}

static void carp_set_state(struct carp_priv *cp, enum carp_state state)
{
	log("%s: Setting CARP state from %d to %d.\n", __func__, cp->state, state);
	cp->state = state;

	switch (state)
	{
		case MASTER:
			carp_call_queue(MASTER_QUEUE);
			if (!timer_pending(&cp->adv_timer))
				mod_timer(&cp->adv_timer, jiffies + cp->adv_timeout*HZ);
			break;
		case BACKUP:
			carp_call_queue(BACKUP_QUEUE);
			if (!timer_pending(&cp->md_timer))
				mod_timer(&cp->md_timer, jiffies + cp->md_timeout*HZ);
			break;
		case INIT:
			if (!timer_pending(&cp->md_timer))
				mod_timer(&cp->md_timer, jiffies + cp->md_timeout*HZ);
			break;
	}
}

static void carp_master_down(unsigned long data)
{
	struct carp_priv *cp = (struct carp_priv *)data;

	//log("%s: state=%d.\n", __func__, cp->state);

	if (cp->state != MASTER)
	{
		if (test_bit(CARP_DATA_AVAIL, (long *)&cp->flags))
		{
			if (!timer_pending(&cp->md_timer))
				mod_timer(&cp->md_timer, jiffies + cp->md_timeout*HZ);
		}
		else
			carp_set_state(cp, MASTER);
	}

	clear_bit(CARP_DATA_AVAIL, (long *)&cp->flags);
}

static int carp_rcv(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct carp_priv *cp = netdev_priv(carp_dev);
	struct carp_header *ch;
	int err = 0;
	u64 tmp_counter;
	struct timeval cptv, chtv;

	//log("%s: state=%d\n", __func__, cp->state);

	spin_lock(&cp->lock);

	iph = ip_hdr(skb);
	ch = (struct carp_header *)skb->data;

	//dump_carp_header(ch);

	if (ch->carp_version != cp->hdr.carp_version)
	{
		log("CARP version mismatch: remote=%d, local=%d.\n",
			ch->carp_version, cp->hdr.carp_version);
		cp->cstat.ver_errors++;
		goto err_out_skb_drop;
	}

	if (ch->carp_vhid != cp->hdr.carp_vhid)
	{
		log("CARP virtual host id mismatch: remote=%d, local=%d.\n",
			ch->carp_vhid, cp->hdr.carp_vhid);
		cp->cstat.vhid_errors++;
		goto err_out_skb_drop;
	}

	if (carp_hmac_verify(cp, ch))
	{
		log("HMAC mismatch.\n");
		cp->cstat.hmac_errors++;
		goto err_out_skb_drop;
	}

	tmp_counter = ntohl(ch->carp_counter[0]);
	tmp_counter = tmp_counter<<32;
	tmp_counter += ntohl(ch->carp_counter[1]);

	if (cp->state == BACKUP && ++cp->carp_adv_counter != tmp_counter)
	{
		log("Counter mismatch: remote=%llu, local=%llu.\n", tmp_counter, cp->carp_adv_counter);
		cp->cstat.counter_errors++;
		goto err_out_skb_drop;
	}

	cptv.tv_sec = cp->hdr.carp_advbase;
	if (cp->hdr.carp_advbase <  240)
		cptv.tv_usec = 240 * 1000000 / 256;
	else
		cptv.tv_usec = cp->hdr.carp_advskew * 1000000 / 256;

	chtv.tv_sec = ch->carp_advbase;
	chtv.tv_usec = ch->carp_advskew * 1000000 / 256;

	/*log("local=%lu.%lu, remote=%lu.%lu, lcounter=%llu, remcounter=%llu, state=%d\n",
			cptv.tv_sec, cptv.tv_usec,
			chtv.tv_sec, chtv.tv_usec,
			cp->carp_adv_counter, tmp_counter,
			cp->state);
	*/
	set_bit(CARP_DATA_AVAIL, (long *)&cp->flags);

	switch (cp->state)
	{
		case INIT:
			if (timeval_before(&chtv, &cptv))
			{
				cp->carp_adv_counter = tmp_counter;
				carp_set_state(cp, BACKUP);
			}
			else
			{
				carp_set_state(cp, MASTER);
			}
			break;
		case MASTER:
			if (timeval_before(&chtv, &cptv))
			{
				cp->carp_adv_counter = tmp_counter;
				carp_set_state(cp, BACKUP);
			}
			break;
		case BACKUP:
			if (timeval_before(&cptv, &chtv))
			{
				carp_set_state(cp, MASTER);
			}
			break;
	}

err_out_skb_drop:
	kfree_skb(skb);
	spin_unlock(&cp->lock);

	return err;
}

static int carp_xmit(struct sk_buff *skb, struct net_device *dev)
{
#if 0
	struct carp_priv *cp = netdev_priv(dev);
	struct net_device_stats *stats = &cp->stat;
	struct iphdr  *iph = skb->nh.iph;
	u8     tos;
	u16    df;
	struct rtable *rt;
	struct net_device *tdev;
	u32    dst;
	int    mtu;
	int err;
	int pkt_len = skb->len;
	log("%s\n", __func__);

	skb->ip_summed = CHECKSUM_NONE;
	skb->protocol = htons(ETH_P_IP);

	ip_select_ident(iph, &rt->u.dst, NULL);
	ip_send_check(iph);
	err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev, dst_output);
	if (err == NET_XMIT_SUCCESS || err == NET_XMIT_CN) {
		stats->tx_bytes += pkt_len;
		stats->tx_packets++;
	} else {
		stats->tx_errors++;
		stats->tx_aborted_errors++;
	}
#endif
	return 0;
}

static int carp_ioctl (struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int err = 0;
	struct carp_priv *cp = netdev_priv(dev);
	struct net_device *tdev = NULL;
	struct carp_ioctl_params p;

	log("%s\n", __func__);

	memset(&p, 0, sizeof(p));

	err = -EPERM;
	if (!capable(CAP_NET_ADMIN))
		goto err_out;

	switch (cmd)
	{
#if 0
		case SIOC_SETIPHDR:

			log("Setting new header.\n");

			err = -EFAULT;
			if (copy_from_user(&iph, ifr->ifr_ifru.ifru_data, sizeof(iph)))
				goto err_out;

			err = -EINVAL;
			if (iph.version != 4 || iph.protocol != IPPROTO_CARP || iph.ihl != 5 || !MULTICAST(iph.daddr))
				goto err_out;

			spin_lock(&cp->lock);
			carp_close(cp->dev);

			memcpy(&cp->iph, &iph, sizeof(iph));

			carp_open(cp->dev);
			spin_unlock(&cp->lock);
			break;
#endif
		case SIOC_SETCARPPARAMS:
			err = -EFAULT;
			if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
				goto err_out;

			err = -EINVAL;
			if (carp_check_params(p))
				goto err_out;

			log("Setting new CARP parameters.\n");

			if (memcmp(p.devname, cp->odev->name, IFNAMSIZ) && (tdev = dev_get_by_name(dev_net(carp_dev), p.devname)) != NULL)
				carp_close(cp->dev);

			spin_lock(&cp->lock);

			if (tdev)
			{
				cp->odev->flags = cp->oflags;
				dev_put(cp->odev);

				cp->odev 	= tdev;
				cp->link 	= cp->odev->ifindex;
				cp->oflags 	= cp->odev->flags;
				cp->odev->flags |= IFF_BROADCAST | IFF_ALLMULTI;
			}

			cp->md_timeout = p.md_timeout;
			cp->adv_timeout = p.adv_timeout;

			carp_set_state(cp, p.state);
			memcpy(cp->carp_pad, p.carp_pad, sizeof(cp->carp_pad));
			memcpy(cp->carp_key, p.carp_key, sizeof(cp->carp_key));
			cp->hdr.carp_vhid = p.carp_vhid;
			cp->hdr.carp_advbase = p.carp_advbase;
			cp->hdr.carp_advskew = p.carp_advskew;

			spin_unlock(&cp->lock);
			if (tdev)
				carp_open(cp->dev);
			break;
		case SIOC_GETCARPPARAMS:

			log("Dumping CARP parameters.\n");

			spin_lock(&cp->lock);
			p.state = cp->state;
			memcpy(p.carp_pad, cp->carp_pad, sizeof(cp->carp_pad));
			memcpy(p.carp_key, cp->carp_key, sizeof(cp->carp_key));
			p.carp_vhid = cp->hdr.carp_vhid;
			p.carp_advbase = cp->hdr.carp_advbase;
			p.carp_advskew = cp->hdr.carp_advskew;
			p.md_timeout = cp->md_timeout;
			p.adv_timeout = cp->adv_timeout;
			memcpy(p.devname, cp->odev->name, sizeof(p.devname));
			p.devname[sizeof(p.devname) - 1] = '\0';
			spin_unlock(&cp->lock);

			err = -EFAULT;
			if (copy_to_user(ifr->ifr_ifru.ifru_data, &p, sizeof(p)))
				goto err_out;
			break;
		default:
			err = -EINVAL;
			break;

	}
	err = 0;

err_out:
	return err;
}

static struct net_device_stats *carp_get_stats(struct net_device *dev)
{
	struct carp_priv *cp = netdev_priv(dev);
	struct carp_stat *cs = &cp->cstat;

	log("%s: crc=%8d, ver=%8d, mem=%8d, xmit=%8d | bytes_sent=%8d\n",
			__func__,
			cs->crc_errors, cs->ver_errors, cs->mem_errors, cs->xmit_errors,
			cs->bytes_sent);
	return &(cp->stat);
}

static int carp_change_mtu(struct net_device *dev, int new_mtu)
{
	log("%s\n", __func__);
	dev->mtu = new_mtu;
	return 0;
}

static const struct net_device_ops carp_netdev_ops = {
    .ndo_init            = carp_init,
    .ndo_uninit          = carp_uninit,
    .ndo_open            = carp_open,
    .ndo_stop            = carp_close,
    .ndo_do_ioctl        = carp_ioctl,
    .ndo_change_mtu      = carp_change_mtu,
    .ndo_start_xmit      = carp_xmit,
//    .ndo_validate_addr   = eth_validate_addr,
//    .ndo_set_rx_mode     = set_multicast_list,
//    .ndo_set_mac_address = carp_set_address,
    .ndo_get_stats       = carp_get_stats,
//    .ndo_get_stats64     = carp_get_stats64,
};

static void carp_setup(struct net_device *dev)
{
	log("%s\n", __func__);

//  FIXME: missing
//    dev->owner = THIS_MODULE;

    dev->netdev_ops      = &carp_netdev_ops;
	dev->destructor      = free_netdev;

	dev->type            = ARPHRD_ETHER;
	dev->hard_header_len = LL_MAX_HEADER;
	dev->mtu             = 1500;
	dev->flags           = IFF_NOARP;
	dev->iflink          = 0;
	dev->addr_len        = 4;
}

static int carp_open(struct net_device *dev)
{
	struct carp_priv *cp = netdev_priv(dev);
	struct rtable *rt;
	struct flowi4 fl4 = {
        .flowi4_oif   = cp->link,
        .daddr        = cp->iph.daddr,
        .saddr        = cp->iph.saddr,
        .flowi4_tos   = RT_TOS(cp->iph.tos),
        .flowi4_proto = IPPROTO_CARP,
    };

	rt = ip_route_output_key(dev_net(dev), &fl4);
    if (rt == NULL)
        return -EADDRNOTAVAIL;

	dev = rt->dst.dev;
	ip_rt_put(rt);
	if (in_dev_get(dev) == NULL)
		return -EADDRNOTAVAIL;
	cp->mlink = dev->ifindex;
	ip_mc_inc_group(in_dev_get(dev), cp->iph.daddr);

	return 0;
}

static int carp_close(struct net_device *dev)
{
	struct carp_priv *cp = netdev_priv(dev);
	struct in_device *in_dev = inetdev_by_index(dev_net(dev), cp->mlink);

	if (in_dev) {
		ip_mc_dec_group(in_dev, cp->iph.daddr);
		in_dev_put(in_dev);
	}
	return 0;
}

static int carp_init(struct net_device *dev)
{
	struct net_device *tdev = NULL;
	struct carp_priv *cp;
	struct iphdr *iph;
	int hlen = LL_MAX_HEADER;
	int mtu = 1500;

	log("%s - %s\n", __func__, dev->name);
	cp = netdev_priv(dev);
	iph = &cp->iph;

	if (!iph->daddr || !MULTICAST(iph->daddr) || !iph->saddr)
		return -EINVAL;

	dev_hold(dev);

	cp->dev = dev;
	strncpy(cp->name, dev->name, IFNAMSIZ);

	ip_eth_mc_map(cp->iph.daddr, dev->dev_addr);
	memcpy(dev->broadcast, &iph->daddr, 4);

	{
        struct flowi4 fl4 = {
            .flowi4_oif   = cp->link,
            .daddr        = iph->daddr,
            .saddr        = iph->saddr,
            .flowi4_tos   = RT_TOS(iph->tos),
            .flowi4_proto = IPPROTO_CARP,
        };
		struct rtable *rt;

        rt = ip_route_output_key(dev_net(dev), &fl4);
        if (rt != NULL) {
			tdev = rt->dst.dev;
			ip_rt_put(rt);
        }
	}

	cp->oflags 		= cp->odev->flags;
	dev->flags 		|= IFF_BROADCAST | IFF_ALLMULTI;
	cp->odev->flags 	|= IFF_BROADCAST | IFF_ALLMULTI;

    dev->netdev_ops = &carp_netdev_ops;

	if (!tdev && cp->link)
		tdev = __dev_get_by_index(dev_net(carp_dev), cp->link);

	if (tdev) {
		hlen = tdev->hard_header_len;
		mtu = tdev->mtu;
	}
	dev->iflink = cp->link;

	dev->hard_header_len = hlen;
	dev->mtu = mtu;

	return 0;
}

static struct net_protocol carp_protocol = {
	.handler     = carp_rcv,
	.err_handler = carp_err,
//    .no_policy   = 1,
//    .netns_ok    = 1,
};

static u32 inline addr2val(u8 a1, u8 a2, u8 a3, u8 a4)
{
	u32 ret;

	ret = ((a1 << 24) | (a2 << 16) | (a3 << 8) | (a4 << 0));

	return htonl(ret);
}

static void carp_advertise(unsigned long data)
{
	struct carp_priv *cp = (struct carp_priv *)data;
	struct carp_header *ch = &cp->hdr;
	struct carp_stat *cs = &cp->cstat;
	struct sk_buff *skb;
	int len;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct carp_header *c;

	if (cp->state == BACKUP || !cp->odev)
		return;

	len = sizeof(struct iphdr) + sizeof(struct carp_header) + sizeof(struct ethhdr);

	skb = alloc_skb(len + 2, GFP_ATOMIC);
	if (!skb)
	{
		log("Failed to allocate new carp frame.\n");
		cs->mem_errors++;
		goto out;
	}

	skb_reserve(skb, 16);
	eth = (struct ethhdr *) skb_push(skb, 14);
	ip = (struct iphdr *)skb_put(skb, sizeof(struct iphdr));
	c = (struct carp_header *)skb_put(skb, sizeof(struct carp_header));

	memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

	ip_eth_mc_map(cp->iph.daddr, eth->h_dest);
	memcpy(eth->h_source, cp->odev->dev_addr, ETH_ALEN);
	eth->h_proto 	= htons(ETH_P_IP);

	ip->ihl      = 5;
	ip->version  = 4;
	ip->tos      = 0;
	ip->tot_len  = htons(len - sizeof(struct ethhdr));
	ip->frag_off = 0;
	ip->ttl      = CARP_TTL;
	ip->protocol = IPPROTO_CARP;
	ip->check    = 0;
	ip->saddr    = cp->iph.saddr;
	ip->daddr    = cp->iph.daddr;
	get_random_bytes(&ip->id, 2);
	ip_send_check(ip);

	memcpy(c, ch, sizeof(struct carp_header));

	spin_lock(&cp->lock);
	cp->carp_adv_counter++;
	spin_unlock(&cp->lock);

	ch->carp_counter[1] = htonl(cp->carp_adv_counter & 0xffffffff);
	ch->carp_counter[0] = htonl((cp->carp_adv_counter >> 32) & 0xffffffff);
	carp_hmac_sign(cp, ch);

	skb->protocol   = __constant_htons(ETH_P_IP);
	skb->mac_header = (sk_buff_data_t)((u8 *)ip) - 14;
	skb->dev        = cp->odev;
	skb->pkt_type   = PACKET_MULTICAST;

    netif_tx_lock(cp->odev);
	if (!netif_queue_stopped(cp->odev))
	{
		atomic_inc(&skb->users);

		if (cp->odev->netdev_ops->ndo_start_xmit(skb, cp->odev))
		{
			atomic_dec(&skb->users);
			cs->xmit_errors++;
			log("Hard xmit error.\n");
		}
		cs->bytes_sent += len;
	}
    netif_tx_unlock(cp->odev);

	mod_timer(&cp->adv_timer, jiffies + cp->adv_timeout*HZ);

	kfree_skb(skb);
out:
	return;
}

static int __init device_carp_init(void)
{
	int err;
	struct carp_priv *cp;

	printk(KERN_INFO "CARP driver.\n");

	carp_dev = alloc_netdev(sizeof(struct carp_priv), "carp0",  carp_setup);
	if (!carp_dev)
	{
		printk(KERN_ERR "Failed to allocate CARP network device structure.\n");
		return -ENOMEM;
	}

	if (inet_add_protocol(&carp_protocol, IPPROTO_CARP) < 0)
	{
		printk(KERN_INFO "Failed to add CARP protocol.\n");
		err = -EAGAIN;
		goto err_out_mem_free;
	}

    carp_dev->netdev_ops = &carp_netdev_ops;

	cp = netdev_priv(carp_dev);
	cp->iph.saddr   = addr2val(10, 0, 0, 3);
	cp->iph.daddr   = addr2val(224, 0, 1, 10);
	cp->iph.tos     = 0;
	cp->md_timeout  = 3;
	cp->adv_timeout = 1;
	cp->state       = INIT;

	spin_lock_init(&cp->lock);
	printk(KERN_INFO "carp: created spin lock.\n");

	cp->odev = dev_get_by_name(dev_net(carp_dev), "eth0");
	if (cp->odev)
	{
		cp->link      = cp->odev->ifindex;
		cp->iph.saddr = (in_dev_get(cp->odev))->ifa_list[0].ifa_address;
	}

	memset(cp->carp_key, 1, sizeof(cp->carp_key));
	get_random_bytes(&cp->carp_adv_counter, 8);

	get_random_bytes(&cp->hdr.carp_advskew, 1);
	get_random_bytes(&cp->hdr.carp_advbase, 1);

	dump_addr_info(cp);

	init_timer(&cp->md_timer);
	cp->md_timer.expires   = jiffies + cp->md_timeout*HZ;
	cp->md_timer.data      = (unsigned long)cp;
	cp->md_timer.function  = carp_master_down;

	init_timer(&cp->adv_timer);
	cp->adv_timer.expires  = jiffies + cp->adv_timeout*HZ;
	cp->adv_timer.data     = (unsigned long)cp;
	cp->adv_timer.function = carp_advertise;

	cp->tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
	if (!cp->tfm)
	{
		printk(KERN_ERR "Failed to allocate SHA1 tfm.\n");
		err = -EINVAL;
		goto err_out_del_protocol;
	}

	dump_hmac_params(cp);

	err = carp_init_queues();
	if (err)
		goto err_out_crypto_free;

	if ((err = register_netdev(carp_dev)))
		goto err_out_fini_carp_queues;

	add_timer(&cp->md_timer);

	return err;

err_out_fini_carp_queues:
	carp_fini_queues();
err_out_crypto_free:
	crypto_free_hash(cp->tfm);
err_out_del_protocol:
	inet_del_protocol(&carp_protocol, IPPROTO_CARP);
err_out_mem_free:
	free_netdev(carp_dev);

	return err;
}

void device_carp_fini(void)
{
	struct carp_priv *cp = netdev_priv(carp_dev);

	carp_fini_queues();

	if (inet_del_protocol(&carp_protocol, IPPROTO_CARP) < 0)
		printk(KERN_INFO "Failed to remove CARP protocol handler.\n");

	crypto_free_hash(cp->tfm);

	unregister_netdev(carp_dev);
}

module_init(device_carp_init);
module_exit(device_carp_fini);
MODULE_LICENSE("GPL");
