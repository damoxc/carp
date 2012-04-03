/*
 * carp_proto.c -- Handlers of the carp protocol
 *
 * Copyright (c) 2012 Damien Churchill <damoxc@gmail.com>
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

#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>

#include <net/checksum.h>
#include <net/ip.h>
#include <net/protocol.h>

#include "carp.h"
#include "carp_log.h"


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

/*----------------------------- Crypto functions ----------------------------*/
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

static int carp_hmac_verify(struct carp *carp, struct carp_header *carp_hdr)
{
    u8 tmp_md[CARP_SIG_LEN];
    struct scatterlist sg;
    int res;

    sg_set_buf(&sg, carp_hdr->carp_counter, sizeof(carp_hdr->carp_counter));
    memset(tmp_md, 1, sizeof(tmp_md));

    res = carp_crypto_hmac(carp, &sg, tmp_md);
    if (res)
        return res;

    return memcmp(tmp_md, carp_hdr->carp_md, CARP_SIG_LEN);
}

/*----------------------------- Proto  functions ----------------------------*/
static void carp_proto_adv(struct carp *carp)
{
    struct carp_header *ch = &carp->hdr;
    struct carp_stat *cs = &carp->cstat;
    struct sk_buff *skb;
    int len;
    unsigned short sum;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct carp_header *c;

    if (carp->state == BACKUP || !carp->odev)
    	return;

    carp_dbg("%s: sending advertisement", carp->name);

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

    ch->carp_type    = CARP_ADVERTISEMENT;
    ch->carp_version = CARP_VERSION;
    ch->carp_pad1    = 0;

    ch->carp_counter[0] = htonl((carp->carp_adv_counter >> 32) & 0xffffffff);
    ch->carp_counter[1] = htonl(carp->carp_adv_counter & 0xffffffff);

    carp_hmac_sign(carp, ch);

    /* Calculate the CARP packets checksum */
    ch->carp_cksum = 0;
    sum = cksum(ch, sizeof(struct carp_header));
    ch->carp_cksum = htons(sum);

    dump_carp_header(ch);

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
    		carp_dbg("Hard xmit error.\n");
    	}
    	cs->bytes_sent += len;
    }
    netif_tx_unlock(carp->odev);

    mod_timer(&carp->adv_timer, jiffies + carp->adv_timeout*HZ);

    kfree_skb(skb);
out:
    return;
}

static void carp_proto_err(struct sk_buff *skb, u32 info)
{
    carp_dbg("%s\n", __func__);
    kfree_skb(skb);
}

static int carp_proto_rcv(struct sk_buff *skb)
{
    int err = 0;
    struct iphdr *iph;
    struct carp *carp;
    struct carp_header *carp_hdr;
    u64 tmp_counter;
    struct timeval carp_tv, carp_hdr_tv;

    iph = ip_hdr(skb);
    carp_hdr = (struct carp_header *)skb->data;


    carp = carp_get_by_vhid(carp_hdr->carp_vhid);
    if (carp == NULL)
        goto err_out_skb_drop;

    carp_dbg("carp: received packet (saddr=%pI4)\n", &(iph->saddr));
    dump_carp_header(carp_hdr);

    spin_lock(&carp->lock);

    if (carp_hdr->carp_version != carp->hdr.carp_version)
    {
    	carp_dbg("%s: version mismatch: remote=%d, local=%d.\n",
    		carp->name, carp_hdr->carp_version, carp->hdr.carp_version);
    	carp->cstat.ver_errors++;
    	goto err_out_skb_drop;
    }

    if (carp_hmac_verify(carp, carp_hdr))
    {
    	carp_dbg("%s: HMAC mismatch on received advertisement.\n", carp->name);
    	carp->cstat.hmac_errors++;
    	goto err_out_skb_drop;
    }

    tmp_counter = ntohl(carp_hdr->carp_counter[0]);
    tmp_counter = tmp_counter<<32;
    tmp_counter += ntohl(carp_hdr->carp_counter[1]);

    if (carp->state == BACKUP && ++carp->carp_adv_counter != tmp_counter)
    {
    	carp_dbg("Counter mismatch: remote=%llu, local=%llu.\n", tmp_counter, carp->carp_adv_counter);
    	carp->cstat.counter_errors++;
    	goto err_out_skb_drop;
    }

    carp_tv.tv_sec = carp->hdr.carp_advbase;
    if (carp->hdr.carp_advbase <  240)
    	carp_tv.tv_usec = 240 * 1000000 / 256;
    else
    	carp_tv.tv_usec = carp->hdr.carp_advskew * 1000000 / 256;

    carp_hdr_tv.tv_sec = carp_hdr->carp_advbase;
    carp_hdr_tv.tv_usec = carp_hdr->carp_advskew * 1000000 / 256;

    /*carp_dbg("local=%lu.%lu, remote=%lu.%lu, lcounter=%llu, remcounter=%llu, state=%d\n",
    		carptv.tv_sec, carptv.tv_usec,
    		carp_hdr_tv.tv_sec, carp_hdr_tv.tv_usec,
    		carp->carp_adv_counter, tmp_counter,
    		carp->state);
    */
    set_bit(CARP_DATA_AVAIL, (long *)&carp->flags);

    switch (carp->state)
    {
    	case INIT:
    		if (timeval_before(&carp_hdr_tv, &carp_tv))
    		{
    			carp->carp_adv_counter = tmp_counter;
    			carp_set_state(carp, BACKUP);
    		}
    		else
    		{
    			carp_set_state(carp, MASTER);
    		}
    		break;
    	case MASTER:
    		if (timeval_before(&carp_hdr_tv, &carp_tv))
    		{
    			carp->carp_adv_counter = tmp_counter;
    			carp_set_state(carp, BACKUP);
    		}
    		break;
    	case BACKUP:
    		if (timeval_before(&carp_tv, &carp_hdr_tv))
    		{
    			carp_set_state(carp, MASTER);
    		}
    		break;
    }

err_out_skb_drop:
    kfree_skb(skb);
    if (carp != NULL)
        spin_unlock(&carp->lock);
    return err;
}

void carp_advertise(unsigned long data)
{
    struct carp *carp = (struct carp *)data;
    carp_proto_adv(carp);
}

/*-------------------------- Registration functions --------------------------*/
static struct net_protocol carp_protocol __read_mostly = {
    .handler     = carp_proto_rcv,
    .err_handler = carp_proto_err,
};

int carp_register_protocol(void)
{
    int res;
    carp_dbg("Registering CARP protocol on %d", IPPROTO_CARP);

    res = inet_add_protocol(&carp_protocol, IPPROTO_CARP);
    if (res)
        return res;

    return 0;
}

int carp_unregister_protocol(void)
{
    int res;
    carp_dbg("Unregistering CARP protocol");

    res = inet_del_protocol(&carp_protocol, IPPROTO_CARP);
    if (res)
        return res;

    return 0;
}
