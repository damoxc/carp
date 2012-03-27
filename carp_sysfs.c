/*
 * carp_sysfs.c -- sysfs interface to carp module
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
#include <linux/module.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/sysfs.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <linux/nsproxy.h>

#include "carp.h"

static ssize_t carp_show_carps(struct class *cls,
                               struct class_attribute *attr,
                               char *buf)
{
    struct carp_net *cn =
        container_of(attr, struct carp_net, class_attr_carp);
    int res = 0;
    struct carp *carp;

    rtnl_lock();

    rtnl_unlock();
    return res;
}

static ssize_t carp_store_carps(struct class *cls,
                                struct class_attribute *attr,
                                const char *buffer, ssize_t count)
{
    return 0;
}

static const void *carp_namespace(struct class *cls,
                                  const struct class_attribute *attr)
{
    const struct carp_net *cn =
        container_of(attr, struct carp_net, class_attr_carp);
    return cn->net;
}

static const struct class_attribute class_attr_carp = {
    .attr = {
        .name = "carp",
        .mode = S_IWUSR | S_IRUGO,
    },
    .show  = carp_show_carps,
    .store = carp_store_carps,
    .namespace = carp_namespace,
};

static ssize_t carp_show_adv_skew(struct device *d,
                                  struct device_attribute *attr,
                                  const char *buf)
{
    return 0;
}


static DEVICE_ATTR(adv_skew, S_IRUGO, carp_show_adv_skew, NULL);

static struct attribute *per_carp_attrs[] = {
    &dev_attr_adv_skew.attr,
    NULL,
};

static struct attribute_group carp_group = {
    .name  = "carp",
    .attrs = per_carp_attrs
};

/*
 * Initialise sysfs. This sets up the carpctl file in /sys/class/net.
 */
int carp_create_sysfs(struct carp_net *cn)
{
    int ret;

    cn->class_attr_carp = class_attr_carp;
    sysfs_attr_init(&cn->class_attr_carp);

    ret = netdev_class_create_file(&cn->class_attr_carp);

    return ret;
}

void carp_destroy_sysfs(struct carp_net *cn)
{
}

/*
 * Initialise sysfs for each carp. This sets up and registers
 * the 'carpctl' directory for each individual carp under /sys/class/net.
 */
void carp_prepare_sysfs_group(struct carp *carp)
{
    carp->dev->sysfs_groups[0] = &carp_group;
}
