/*
 *     carp.c
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
#include <linux/etherdevice.h>
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
#include <net/net_namespace.h>
#include <net/netns/generic.h>

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

static int max_carps = 1;
static int tx_queues = CARP_DEFAULT_TX_QUEUES;

/*---------------------------- Module parameters ----------------------------*/
module_param(max_carps, int, 0);
MODULE_PARM_DESC(max_cards, "Max number of carp devices");
module_param(tx_queues, int, 0);
MODULE_PARM_DESC(tx_queues, "Max number of transmit queues (default = 16)");

/*----------------------------- Global variables ----------------------------*/

int carp_net_id __read_mostly;

static int carp_dev_init(struct net_device *);
static void carp_dev_uninit(struct net_device *);
static void carp_dev_setup(struct net_device *);
static int carp_dev_close(struct net_device *);
static int carp_dev_open(struct net_device *);
static int carp_dev_ioctl (struct net_device *, struct ifreq *, int);
static int carp_check_params(struct carp *, struct carp_ioctl_params);

static int carp_dev_xmit(struct sk_buff *, struct net_device *);

static struct net_device_stats *carp_dev_get_stats(struct net_device *);

static u32 inline addr2val(u8, u8, u8, u8);

static void carp_master_down(unsigned long);
static void carp_advertise(unsigned long);

static int  __init carp_init(void);
static void __exit carp_exit(void);

/*----------------------------- Global functions ----------------------------*/
int carp_crypto_hmac(struct carp *carp, struct scatterlist *sg, u8 *carp_md)
{
    int res;
    struct hash_desc desc;

    res = crypto_hash_setkey(carp->hash, carp->carp_key, sizeof(carp->carp_key));
    if (res)
        return res;

    desc.tfm   = carp->hash;
    desc.flags = 0;

    res = crypto_hash_digest(&desc, sg, sg->length, carp_md);
    if (res);
        return res;

    return 0;
}

static void carp_hmac_sign(struct carp *carp, struct carp_header *carp_hdr)
{
    struct scatterlist sg;
    sg_set_buf(&sg, carp_hdr->carp_counter, sizeof(carp_hdr->carp_counter));
    carp_crypto_hmac(carp, &sg, carp_hdr->carp_md);
}

static unsigned short cksum(const void * const buf_, const size_t len)
{
    const unsigned char *buf = (unsigned char *) buf_;
    unsigned long sum = 0UL;
    size_t evenlen = len & ~ (size_t) 1U;
    size_t i = (size_t) 0U;

    if (len <= (size_t) 0U) {
        return 0U;
    }
    do {
        sum += (buf[i] << 8) | buf[i + 1];
        if (sum > 0xffff) {
            sum &= 0xffff;
            sum++;
        }
        i += 2;
    } while (i < evenlen);
    if (i != evenlen) {
        sum += buf[i] << 8;
        if (sum > 0xffff) {
            sum &= 0xffff;
            sum++;
        }
    }
    return (unsigned short) ~sum;
}

/*----------------------------- Device functions ----------------------------*/
static void carp_dev_uninit(struct net_device *dev)
{
    struct carp *carp = netdev_priv(dev);

    if (timer_pending(&carp->md_timer))
    	del_timer_sync(&carp->md_timer);
    if (timer_pending(&carp->adv_timer))
    	del_timer_sync(&carp->adv_timer);

    carp_remove_proc_entry(carp);

    crypto_free_hash(carp->hash);

    dev_put(carp->odev);
    dev_put(dev);
}

static int carp_check_params(struct carp *carp, struct carp_ioctl_params p)
{
    carp_dbg("%s\n", __func__);
    if (p.state != INIT && p.state != BACKUP && p.state != MASTER)
    {
    	log("Wrong state %d.\n", p.state);
    	return -1;
    }

    if (!__dev_get_by_name(dev_net(carp->dev), p.devname))
    {
    	log("No such device %s.\n", p.devname);
    	return -2;
    }

    if (p.md_timeout > MAX_MD_TIMEOUT || p.adv_timeout > MAX_ADV_TIMEOUT ||
        !p.md_timeout || !p.adv_timeout)
    	return -3;

    return 0;
}

void carp_set_state(struct carp *carp, enum carp_state state)
{
    carp_dbg("%s\n", __func__);
    pr_info("%s: Setting CARP state from %d to %d.\n", __func__, carp->state, state);
    carp->state = state;

    switch (state)
    {
    	case MASTER:
    		carp_call_queue(MASTER_QUEUE);
    		if (!timer_pending(&carp->adv_timer))
    			mod_timer(&carp->adv_timer, jiffies + carp->adv_timeout*HZ);
    		break;
    	case BACKUP:
    		carp_call_queue(BACKUP_QUEUE);
    		if (!timer_pending(&carp->md_timer))
    			mod_timer(&carp->md_timer, jiffies + carp->md_timeout*HZ);
    		break;
    	case INIT:
    		if (!timer_pending(&carp->md_timer))
    			mod_timer(&carp->md_timer, jiffies + carp->md_timeout*HZ);
    		break;
    }
}

static void carp_master_down(unsigned long data)
{
    struct carp *carp = (struct carp *)data;
    carp_dbg("%s\n", __func__);

    //log("%s: state=%d.\n", __func__, cp->state);

    if (carp->state != MASTER)
    {
    	if (test_bit(CARP_DATA_AVAIL, (long *)&carp->flags))
    	{
    		if (!timer_pending(&carp->md_timer))
    			mod_timer(&carp->md_timer, jiffies + carp->md_timeout*HZ);
    	}
    	else
    		carp_set_state(carp, MASTER);
    }

    clear_bit(CARP_DATA_AVAIL, (long *)&carp->flags);
}

static int carp_dev_xmit(struct sk_buff *skb, struct net_device *carp_dev)
{
    carp_dbg("%s\n", __func__);
#if 0
    struct carp *cp = netdev_priv(dev);
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

static int carp_dev_ioctl (struct net_device *carp_dev, struct ifreq *ifr, int cmd)
{
    int err = 0;
    struct carp *carp = netdev_priv(carp_dev);
    //struct carp_net *cn = net_generic(dev_net(carp_dev), carp_net_id);

    struct net_device *tdev = NULL;
    struct carp_ioctl_params p;

    carp_dbg("%s\n", __func__);

    memset(&p, 0, sizeof(p));

    err = -EPERM;
    if (!capable(CAP_NET_ADMIN))
    	goto err_out;

    switch (cmd)
    {
    	case SIOC_SETCARPPARAMS:
    		err = -EFAULT;
    		if (copy_from_user(&p, ifr->ifr_ifru.ifru_data, sizeof(p)))
    			goto err_out;

    		err = -EINVAL;
    		if (carp_check_params(carp, p))
    			goto err_out;

    		carp_dbg("Setting new CARP parameters.\n");

    		if (memcmp(p.devname, carp->odev->name, IFNAMSIZ) && (tdev = dev_get_by_name(dev_net(carp_dev), p.devname)) != NULL)
    			carp_dev_close(carp->dev);


    		spin_lock(&carp->lock);

    		if (tdev)
    		{
    			carp->odev->flags = carp->oflags;
    			dev_put(carp->odev);

    			carp->odev 	= tdev;
    			carp->link 	= carp->odev->ifindex;
    			carp->oflags 	= carp->odev->flags;
    			carp->odev->flags |= IFF_BROADCAST | IFF_ALLMULTI;
    		}

    		carp->md_timeout = p.md_timeout;
    		carp->adv_timeout = p.adv_timeout;

    		carp_set_state(carp, p.state);
    		memcpy(carp->carp_pad, p.carp_pad, sizeof(carp->carp_pad));
    		memcpy(carp->carp_key, p.carp_key, sizeof(carp->carp_key));
    		carp->hdr.carp_vhid = p.carp_vhid;
    		carp->hdr.carp_advbase = p.carp_advbase;
    		carp->hdr.carp_advskew = p.carp_advskew;

    		spin_unlock(&carp->lock);
    		if (tdev)
    			carp_dev_open(carp->dev);
    		break;
    	case SIOC_GETCARPPARAMS:

    		carp_dbg("Dumping CARP parameters.\n");

    		spin_lock(&carp->lock);
    		p.state = carp->state;
    		memcpy(p.carp_pad, carp->carp_pad, sizeof(carp->carp_pad));
    		memcpy(p.carp_key, carp->carp_key, sizeof(carp->carp_key));
    		p.carp_vhid = carp->hdr.carp_vhid;
    		p.carp_advbase = carp->hdr.carp_advbase;
    		p.carp_advskew = carp->hdr.carp_advskew;
    		p.md_timeout = carp->md_timeout;
    		p.adv_timeout = carp->adv_timeout;
    		memcpy(p.devname, carp->odev->name, sizeof(p.devname));
    		p.devname[sizeof(p.devname) - 1] = '\0';
    		spin_unlock(&carp->lock);

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

static struct net_device_stats *carp_dev_get_stats(struct net_device *carp_dev)
{
    struct carp *carp = netdev_priv(carp_dev);
    struct carp_stat *cs = &carp->cstat;

    carp_dbg("%s: crc=%8d, ver=%8d, mem=%8d, xmit=%8d | bytes_sent=%8d\n",
    		__func__,
    		cs->crc_errors, cs->ver_errors, cs->mem_errors, cs->xmit_errors,
    		cs->bytes_sent);
    return &(carp->stat);
}

static int carp_dev_change_mtu(struct net_device *carp_dev, int new_mtu)
{
    carp_dev->mtu = new_mtu;
    return 0;
}

static int carp_set_mac_address(struct net_device *carp_dev, void *addr)
{
    struct carp *carp = netdev_priv(carp_dev);
    struct sockaddr *address = addr;

    if (!is_valid_ether_addr(address->sa_data))
        return -EADDRNOTAVAIL;

    memcpy(carp_dev->dev_addr, address->sa_data, carp_dev->addr_len);
    memcpy(carp->hwaddr, address->sa_data, carp_dev->addr_len);
    return 0;
}

static const struct net_device_ops carp_netdev_ops = {
    .ndo_init            = carp_dev_init,
    .ndo_uninit          = carp_dev_uninit,
    .ndo_open            = carp_dev_open,
    .ndo_stop            = carp_dev_close,
    .ndo_do_ioctl        = carp_dev_ioctl,
    .ndo_change_mtu      = carp_dev_change_mtu,
    .ndo_start_xmit      = carp_dev_xmit,
    .ndo_get_stats       = carp_dev_get_stats,
// NOTE: the below were never implemented in the old carp module
//    .ndo_validate_addr   = eth_validate_addr,
//    .ndo_set_rx_mode     = set_multicast_list,
    .ndo_set_mac_address = carp_set_mac_address,
//    .ndo_get_stats64     = carp_get_stats64,
};

static void carp_dev_setup(struct net_device *carp_dev)
{
    int res;
    struct in_device *in_d;
    struct carp *carp = netdev_priv(carp_dev);

    carp_dbg("%s\n", __func__);

    /* Initialise the device entry points */
    carp_dev->netdev_ops = &carp_netdev_ops;

    carp_dev->destructor = free_netdev;

    // FIXME: what happened to the owner field?
    //carp_dev->owner = THIS_MODULE;
    carp_dev->type            = ARPHRD_ETHER;
    carp_dev->hard_header_len = LL_MAX_HEADER;
    carp_dev->mtu             = 1500;
    carp_dev->flags           = IFF_NOARP;
    carp_dev->iflink          = 0;
    carp_dev->addr_len        = 4;

    /* Initialise carp options */
    carp->iph.saddr   = addr2val(10, 0, 0, 3);
    carp->iph.daddr   = MULTICAST_ADDR;
    carp->iph.tos     = 0;
    carp->md_timeout  = 3;
    carp->adv_timeout = 1;
    carp->state       = INIT;

    // FIXME: this needs improving
    /* Set the source IP address to the same as eth0 */
    carp->odev = dev_get_by_name(dev_net(carp_dev), "eth0");
    if (carp->odev) {
        carp->link = carp->odev->ifindex;
        in_d       = in_dev_get(carp->odev);

        if (in_d != NULL && in_d->ifa_list != NULL)
            carp->iph.saddr = in_d->ifa_list[0].ifa_address;
    }

    /* Setup the carp advertisements */
    memset(carp->carp_key, 1, sizeof(carp->carp_key));
    get_random_bytes(&carp->carp_adv_counter, 8);

    carp->hdr.carp_advskew = 0;
    carp->hdr.carp_advbase = 1;

    dump_addr_info(carp);

    init_timer(&carp->md_timer);
    carp->md_timer.expires   = jiffies + carp->md_timeout*HZ;
    carp->md_timer.data      = (unsigned long)carp;
    carp->md_timer.function  = carp_master_down;

    init_timer(&carp->adv_timer);
    carp->adv_timer.expires  = jiffies + carp->adv_timeout*HZ;
    carp->adv_timer.data     = (unsigned long)carp;
    carp->adv_timer.function = carp_advertise;

    carp->hash = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);
    if (!carp->hash) {
        pr_err("Failed to allocate SHA1 hash.\n");
        res = -EINVAL;
        goto out;
    }

    dump_hmac_params(carp);

    res = carp_init_queues();
    if (res)
        goto err_out_crypto_free;

    add_timer(&carp->md_timer);
    return;

err_out_crypto_free:
    crypto_free_hash(carp->hash);
out:
    return;
}

static int carp_dev_open(struct net_device *carp_dev)
{
    struct carp *carp = netdev_priv(carp_dev);
    struct rtable *rt;
    struct flowi4 fl4 = {
        .flowi4_oif   = carp->link,
        .daddr        = carp->iph.daddr,
        .saddr        = carp->iph.saddr,
        .flowi4_tos   = RT_TOS(carp->iph.tos),
        .flowi4_proto = IPPROTO_CARP,
    };
    carp_dbg("%s", __func__);

    rt = ip_route_output_key(dev_net(carp_dev), &fl4);
    if (rt == NULL)
        return -EADDRNOTAVAIL;

    carp_dev = rt->dst.dev;
    ip_rt_put(rt);
    if (in_dev_get(carp_dev) == NULL)
    	return -EADDRNOTAVAIL;
    carp->mlink = carp_dev->ifindex;
    ip_mc_inc_group(in_dev_get(carp_dev), carp->iph.daddr);

    return 0;
}

static int carp_dev_close(struct net_device *carp_dev)
{
    struct carp *carp = netdev_priv(carp_dev);
    struct in_device *in_dev = inetdev_by_index(dev_net(carp_dev), carp->mlink);
    carp_dbg("%s", __func__);

    if (in_dev) {
    	ip_mc_dec_group(in_dev, carp->iph.daddr);
    	in_dev_put(in_dev);
    }
    return 0;
}

/*
 * Called from registration process
 */
static int carp_dev_init(struct net_device *carp_dev)
{
    struct net_device *tdev = NULL;
    struct carp *carp;
    struct iphdr *iph;
    int hlen = LL_MAX_HEADER;
    int mtu = 1500;
    carp_dbg("%s", __func__);

    log("Begin %s for %s\n", __func__, carp_dev->name);
    carp = netdev_priv(carp_dev);
    iph = &carp->iph;

    if (!iph->daddr || !MULTICAST(iph->daddr) || !iph->saddr)
    	return -EINVAL;

    dev_hold(carp_dev);

    carp->dev = carp_dev;
    strncpy(carp->name, carp_dev->name, IFNAMSIZ);

    ip_eth_mc_map(carp->iph.daddr, carp_dev->dev_addr);
    memcpy(carp_dev->broadcast, &iph->daddr, 4);

    {
        struct flowi4 fl4 = {
            .flowi4_oif   = carp->link,
            .daddr        = iph->daddr,
            .saddr        = iph->saddr,
            .flowi4_tos   = RT_TOS(iph->tos),
            .flowi4_proto = IPPROTO_CARP,
        };
    	struct rtable *rt;

        rt = ip_route_output_key(dev_net(carp_dev), &fl4);
        if (!IS_ERR(rt)) {
    		tdev = rt->dst.dev;
    		ip_rt_put(rt);
        }
    }

    carp->oflags      = carp->odev->flags;
    carp_dev->flags   |= IFF_BROADCAST | IFF_ALLMULTI;
    carp->odev->flags |= IFF_BROADCAST | IFF_ALLMULTI;

    carp_dev->netdev_ops = &carp_netdev_ops;

    if (!tdev && carp->link)
    	tdev = __dev_get_by_index(dev_net(carp_dev), carp->link);

    if (tdev) {
    	hlen = tdev->hard_header_len;
    	mtu = tdev->mtu;
    }
    carp_dev->iflink = carp->link;

    carp_dev->hard_header_len = hlen;
    carp_dev->mtu = mtu;

    carp_create_proc_entry(carp);

    return 0;
}

static u32 inline addr2val(u8 a1, u8 a2, u8 a3, u8 a4)
{
    u32 ret;
    ret = ((a1 << 24) | (a2 << 16) | (a3 << 8) | (a4 << 0));
    return htonl(ret);
}

static void carp_advertise(unsigned long data)
{
    struct carp *carp = (struct carp *)data;
    struct carp_header *ch = &carp->hdr;
    struct carp_stat *cs = &carp->cstat;
    struct sk_buff *skb;
    int len;
    unsigned short sum;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct carp_header *c;
    carp_dbg("%s", __func__);

    if (carp->state == BACKUP || !carp->odev)
    	return;

    len = sizeof(struct iphdr) + sizeof(struct carp_header) + sizeof(struct ethhdr);

    skb = alloc_skb(len + 2, GFP_ATOMIC);
    if (!skb)
    {
    	cs->mem_errors++;
    	goto out;
    }

    skb_reserve(skb, 16);
    eth = (struct ethhdr *) skb_push(skb, 14);
    ip = (struct iphdr *)skb_put(skb, sizeof(struct iphdr));
    c = (struct carp_header *)skb_put(skb, sizeof(struct carp_header));

    memset(&(IPCB(skb)->opt), 0, sizeof(IPCB(skb)->opt));

    ip_eth_mc_map(carp->iph.daddr, eth->h_dest);
    memcpy(eth->h_source, carp->odev->dev_addr, ETH_ALEN);
    eth->h_proto 	= htons(ETH_P_IP);

    ip->ihl      = 5;
    ip->version  = 4;
    ip->tos      = 0;
    ip->tot_len  = htons(len - sizeof(struct ethhdr));
    ip->frag_off = 0;
    ip->ttl      = CARP_TTL;
    ip->protocol = IPPROTO_CARP;
    ip->check    = 0;
    ip->saddr    = carp->iph.saddr;
    ip->daddr    = carp->iph.daddr;
    get_random_bytes(&ip->id, 2);
    ip_send_check(ip);


    spin_lock(&carp->lock);
    carp->carp_adv_counter++;
    spin_unlock(&carp->lock);

    ch->carp_type    = 1;
    ch->carp_version = 2;
    ch->carp_counter[1] = htonl(carp->carp_adv_counter & 0xffffffff);
    ch->carp_counter[0] = htonl((carp->carp_adv_counter >> 32) & 0xffffffff);
    carp_hmac_sign(carp, ch);

    /* Calculate the CARP packets checksum */
    ch->carp_cksum = 0;
    sum = cksum(ch, sizeof(struct carp_header));
    ch->carp_cksum = htons(sum);

    memcpy(c, ch, sizeof(struct carp_header));

    skb->protocol   = __constant_htons(ETH_P_IP);
    skb->mac_header = (void *)eth;
    skb->dev        = carp->odev;
    skb->pkt_type   = PACKET_MULTICAST;

    netif_tx_lock(carp->odev);
    if (!netif_queue_stopped(carp->odev))
    {
    	atomic_inc(&skb->users);

    	if (carp->odev->netdev_ops->ndo_start_xmit(skb, carp->odev))
    	{
    		atomic_dec(&skb->users);
    		cs->xmit_errors++;
    		log("Hard xmit error.\n");
    	}
    	cs->bytes_sent += len;
    }
    netif_tx_unlock(carp->odev);

    mod_timer(&carp->adv_timer, jiffies + carp->adv_timeout*HZ);

    kfree_skb(skb);
out:
    return;
}

static int carp_validate(struct nlattr *tb[], struct nlattr *data[])
{
    carp_dbg("%s", __func__);
    if (tb[IFLA_ADDRESS]) {
        if (nla_len(tb[IFLA_ADDRESS]) != ETH_ALEN)
            return -EINVAL;
        if (!is_valid_ether_addr(nla_data(tb[IFLA_ADDRESS])))
            return -EADDRNOTAVAIL;
    }
    return 0;
}

static int carp_get_tx_queues(struct net *net, struct nlattr *tb[],
                              unsigned int *num_queues,
                              unsigned int *real_num_queues)
{
    carp_dbg("%s", __func__);
    return 0;
}

static struct rtnl_link_ops carp_link_ops __read_mostly = {
    .kind          = "carp",
    .priv_size     = sizeof(struct carp),
    .setup         = carp_dev_setup,
    .validate      = carp_validate,
    .get_tx_queues = carp_get_tx_queues,
};

int carp_create(struct net *net, const char *name)
{
    struct net_device *carp_dev;
    int res;
    carp_dbg("%s", __func__);

    rtnl_lock();

    carp_dev = alloc_netdev_mq(sizeof(struct carp),
                               name ? name : "carp%d",
                               carp_dev_setup, tx_queues);
    if (!carp_dev) {
        pr_err("%s: eek! can't alloc netdev!\n", name);
        rtnl_unlock();
        return -ENOMEM;
    }

    dev_net_set(carp_dev, net);
    carp_dev->rtnl_link_ops = &carp_link_ops;

    res = register_netdevice(carp_dev);

    netif_carrier_off(carp_dev);

    rtnl_unlock();
    if (res < 0)
        free_netdev(carp_dev);
    return res;
}

static int __net_init carp_net_init(struct net *net)
{
    struct carp_net *cn = net_generic(net, carp_net_id);
    carp_dbg("%s", __func__);

    cn->net = net;
    INIT_LIST_HEAD(&cn->dev_list);

    carp_create_proc_dir(cn);
    carp_create_sysfs(cn);

    return 0;
}

static void __net_exit carp_net_exit(struct net *net)
{
    struct carp_net *cn = net_generic(net, carp_net_id);
    carp_dbg("%s", __func__);

    carp_destroy_sysfs(cn);
    carp_destroy_proc_dir(cn);
}

static struct pernet_operations carp_net_ops = {
    .init = carp_net_init,
    .exit = carp_net_exit,
    .id   = &carp_net_id,
    .size = sizeof(struct carp_net),
};

static int __init carp_init(void)
{
    int i;
    int res;
    carp_dbg("%s", __func__);

    pr_info("carp: %s", DRV_DESC);

    res = register_pernet_subsys(&carp_net_ops);
    if (res)
        goto out;

    res = carp_register_protocol();
    if (res)
        goto err_proto;

    res = rtnl_link_register(&carp_link_ops);
    if (res)
        goto err_link;

    carp_create_debugfs();

    for (i = 0; i < max_carps; i++) {
        res = carp_create(&init_net, NULL);
        if (res)
            goto err;
    }

out:
    return res;
err:
    carp_dbg("carp: error creating netdev");
    rtnl_link_unregister(&carp_link_ops);
err_link:
    carp_dbg("carp: error registering link");
    carp_unregister_protocol();
err_proto:
    carp_dbg("carp: error registering protocol");
    unregister_pernet_subsys(&carp_net_ops);
    goto out;
}


static void __exit carp_exit(void)
{
    carp_dbg("%s", __func__);
    pr_info("carp: unloading");
    carp_destroy_debugfs();

    rtnl_link_unregister(&carp_link_ops);
    unregister_pernet_subsys(&carp_net_ops);

    carp_fini_queues();

    if (carp_unregister_protocol() < 0)
        pr_info("Failed to remove CARP protocol handler.\n");
}

module_init(carp_init);
module_exit(carp_exit);
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_DESCRIPTION(DRV_DESCRIPTION ", v" DRV_VERSION);
MODULE_AUTHOR("Damien Churchill, Evgeniy Polyakov");
