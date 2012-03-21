/*
 * 	carp_ioctl.h
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

#ifndef __CARP_IOCTL_H
#define __CARP_IOCTL_H

#include <linux/sockios.h>

#define	CARP_KEY_LEN		20
#define	CARP_HMAC_PAD_LEN	64

#define MAX_MD_TIMEOUT		5
#define MAX_ADV_TIMEOUT		5

enum carp_state {INIT = 0, MASTER, BACKUP};

enum carp_ioctls 
{
	SIOC_SETCARPPARAMS = SIOCDEVPRIVATE,
	SIOC_GETCARPPARAMS,
};

struct carp_ioctl_params
{
	__u8		carp_advskew;
	__u8		carp_advbase;
	__u8		carp_vhid;
	__u8 		carp_key[CARP_KEY_LEN];
	__u8 		carp_pad[CARP_HMAC_PAD_LEN];
	enum carp_state	state;
	char 		devname[IFNAMSIZ];
	__u32		md_timeout;
	__u32		adv_timeout;
	
};

#endif /* __CARP_IOCTL_H */
