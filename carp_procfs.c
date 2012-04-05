/*
 * carp_procfs.c -- procfs interface to carp module
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

#include <linux/proc_fs.h>
#include <linux/export.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include "carp.h"
#include "carp_log.h"

static void *carp_info_seq_start(struct seq_file *seq, loff_t *pos)
    __acquires(RCU)
    __acquires(&carp->lock)
{
    struct carp *carp = seq->private;
    carp_dbg("%s: pos=%lld", __func__, *pos);

    rcu_read_lock();
    spin_lock(&carp->lock);

    if (*pos == 0)
        return carp;
    return NULL;
}

static void *carp_info_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
    carp_dbg("%s", __func__);
    ++*pos;
    return NULL;
}

static void carp_info_seq_stop(struct seq_file *seq, void *v)
    __releases(&carp->lock)
    __releases(RCU)
{
    struct carp *carp = seq->private;
    carp_dbg("%s", __func__);
    spin_unlock(&carp->lock);
    rcu_read_unlock();
}

static int carp_info_seq_show(struct seq_file *seq, void *v)
{
    struct carp *carp = seq->private;
    struct carp_stat *carp_stat = &(carp->cstat);

    seq_printf(seq, "%s\n", DRV_DESC);
    seq_printf(seq, "State: %s\n", carp_state_fmt(carp));
    seq_printf(seq, "Device: %s\n", carp->odev->name);
    seq_printf(seq, "Bytes Sent: %d\n", carp_stat->bytes_sent);
    seq_printf(seq, "VHID: %d\n", carp->vhid);
    seq_printf(seq, "Adv Base: %d\n", carp->advbase);
    seq_printf(seq, "Adv Skew: %d\n", carp->advskew);
    seq_printf(seq, "CRC Errors: %d\n", carp_stat->crc_errors);
    seq_printf(seq, "HMAC Errors: %d\n", carp_stat->hmac_errors);
    seq_printf(seq, "Ver Errors: %d\n", carp_stat->ver_errors);
    seq_printf(seq, "Mem Errors: %d\n", carp_stat->mem_errors);
    seq_printf(seq, "Xmit Errors: %d\n", carp_stat->xmit_errors);

    return 0;
}

static const struct seq_operations carp_info_seq_ops = {
    .start = carp_info_seq_start,
    .next  = carp_info_seq_next,
    .stop  = carp_info_seq_stop,
    .show  = carp_info_seq_show,
};

static int carp_info_open(struct inode *inode, struct file *file)
{
    struct seq_file *seq;
    struct proc_dir_entry *proc;
    int res;

    res = seq_open(file, &carp_info_seq_ops);
    if (!res) {
        /* recover the pointer buried in proc_dir_entry data */
        seq = file->private_data;
        proc = PDE(inode);
        seq->private = proc->data;
    }

    return res;
}

static const struct file_operations carp_info_fops = {
    .owner   = THIS_MODULE,
    .open    = carp_info_open,
    .read    = seq_read,
    .llseek  = seq_lseek,
    .release = seq_release,
};

void carp_create_proc_entry(struct carp *carp)
{
    struct net_device *carp_dev = carp->dev;
    struct carp_net *cn = net_generic(dev_net(carp_dev), carp_net_id);

    if (cn->proc_dir) {
        carp->proc_entry = proc_create_data(carp_dev->name,
                                            S_IRUGO, cn->proc_dir,
                                            &carp_info_fops, carp);
        if (carp->proc_entry== NULL)
            pr_warning("Warning: Cannot create /proc/net/%s/%s\n",
                       DRV_NAME, carp_dev->name);
        else
            memcpy(carp->proc_file_name, carp_dev->name, IFNAMSIZ);
    }
}

void carp_remove_proc_entry(struct carp *carp)
{
    struct net_device *carp_dev = carp->dev;
    struct carp_net *cn = net_generic(dev_net(carp_dev), carp_net_id);

    if (cn->proc_dir && carp->proc_entry) {
        remove_proc_entry(carp->proc_file_name, cn->proc_dir);
        memset(carp->proc_file_name, 0, IFNAMSIZ);
        carp->proc_entry = NULL;
    }
}

void __net_init carp_create_proc_dir(struct carp_net *cn)
{
    if (!cn->proc_dir) {
        cn->proc_dir = proc_mkdir(DRV_NAME, cn->net->proc_net);
        if (!cn->proc_dir)
            pr_warning("Warning: cannot create /proc/net/%s\n",
                DRV_NAME);
    }
}

void __net_exit carp_destroy_proc_dir(struct carp_net *cn)
{
    if (cn->proc_dir) {
        remove_proc_entry(DRV_NAME, cn->net->proc_net);
        cn->proc_dir = NULL;
    }
}
