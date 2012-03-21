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

void carp_create_proc_entry(struct carp *carp)
{
    struct net_device *carp_dev = carp->dev;
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
