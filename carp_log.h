/*
 * 	carp_log.h
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

#ifndef __CARP_LOG_H
#define __CARP_LOG_H

#include "carp.h"

#ifdef CONFIG_CARP_DEBUG
#define log(f, a...) printk(KERN_INFO f, ##a)
#else
#define log(f, a...)
#endif

void dump_addr_info(struct carp *);
void dump_hmac_params(struct carp *);
void dump_carp_header(struct carp_header *);

#endif /* __CARP_LOG_H */
