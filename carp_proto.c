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

#include <linux/skbuff.h>
#include <net/protocol.h>

#include "carp.h"
#include "carp_log.h"

/*----------------------------- Global functions ----------------------------*/
static int carp_hmac_verify(struct carp *carp, struct carp_header *carp_hdr)
{
    u8 tmp_md[CARP_SIG_LEN];
    struct scatterlist sg;
    int res;

    sg_set_buf(&sg, carp_hdr->carp_counter, sizeof(carp_hdr->carp_counter));
    memset(tmp_md, 1, sizeof(tmp_md));

    res = carp_crypto_hmac(carp, &sg, carp_hdr->carp_md);
    if (res)
        return res;

    return memcmp(tmp_md, carp_hdr->carp_md, CARP_SIG_LEN);
}

/*----------------------------- Proto  functions ----------------------------*/
static void carp_err(struct sk_buff *skb, u32 info)
{
    carp_dbg("%s\n", __func__);
    kfree_skb(skb);
}

static int carp_rcv(struct sk_buff *skb)
{
    carp_dbg("%s\n", __func__);
    return 0;
#if 0
    struct iphdr *iph;
    struct net_device *carp_dev;
    struct carp *carp = netdev_priv(carp_dev);
    struct carp_header *carp_hdr;
    int err = 0;
    u64 tmp_counter;
    struct timeval carp_tv, carp_hdr_tv;

    //carp_dbg("%s: state=%d\n", __func__, cp->state);

    spin_lock(&carp->lock);

    iph = ip_hdr(skb);
    carp_hdr = (struct carp_header *)skb->data;

    //dump_carp_header(ch);

    if (carp_hdr->carp_version != carp->hdr.carp_version)
    {
    	carp_dbg("CARP version mismatch: remote=%d, local=%d.\n",
    		carp_hdr->carp_version, carp->hdr.carp_version);
    	carp->cstat.ver_errors++;
    	goto err_out_skb_drop;
    }

    if (carp_hdr->carp_vhid != carp->hdr.carp_vhid)
    {
    	carp_dbg("CARP virtual host id mismatch: remote=%d, local=%d.\n",
    		carp_hdr->carp_vhid, carp->hdr.carp_vhid);
    	carp->cstat.vhid_errors++;
    	goto err_out_skb_drop;
    }

    if (carp_hmac_verify(carp, carp_hdr))
    {
    	carp_dbg("HMAC mismatch.\n");
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
    spin_unlock(&carp->lock);

    return err;
#endif
}

/*-------------------------- Registration functions --------------------------*/
static struct net_protocol carp_protocol __read_mostly = {
    .handler     = carp_rcv,
    .err_handler = carp_err,
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
