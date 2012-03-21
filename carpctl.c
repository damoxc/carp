/*
 * 	carpctl.c
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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <linux/if.h>

#include "carp_ioctl.h"

#define	CARP_KEY_LEN		20
#define	CARP_HMAC_PAD_LEN	64
#define IPPROTO_CARP 		112

static void usage(const char *pr)
{
	fprintf(stderr, "Usage: %s: [-h] [-i iph] [-b advbase] [-s advskew] [-d device] [-v vhid] [-k key] [-p pad] [-S state] "
			"[-m md_timeout] [-a adv_timout].\n",
			pr);
}

static void carp_dump_params(struct carp_ioctl_params p)
{
	printf("Attached to device %s.\n", p.devname);
	printf("ADV: base=%d, skew=%d.\n", p.carp_advbase, p.carp_advskew);
	printf("VHID=%d, STATE=%d.\n", p.carp_vhid, p.state);
}

int main(int argc, char *argv[])
{
	int ch, err, s, need_change;
	struct ifreq ifr;
	char devname[IFNAMSIZ] = "carp0";
	struct carp_ioctl_params p;

	memset(&p, 0, sizeof(p));

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, devname, sizeof(ifr.ifr_name));
	ifr.ifr_ifru.ifru_data = (void *)&p;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
	{
		fprintf(stderr, "Failed to create CARP control socket: [%d] %s.\n",
				errno, strerror(errno));
		return -1;
	}

	err = ioctl(s, SIOC_GETCARPPARAMS, &ifr);
	if (err == -1)
	{
		fprintf(stderr, "Failed to call ioctl: [%d] %s.\n",
				errno, strerror(errno));
		close(s);
		return -1;
	}

	carp_dump_params(p);

	need_change = 0;
	while((ch = getopt(argc, argv, "hi:b:s:d:v:k:p:S:m:a:")) != -1)
	{
		need_change = 1;
		switch (ch)
		{
			case 'm':
				p.md_timeout = atoi(optarg);
				break;
			case 'a':
				p.adv_timeout = atoi(optarg);
				break;
			case 'b':
				p.carp_advbase = atoi(optarg);
				break;
			case 's':
				p.carp_advskew = atoi(optarg);
				break;
			case 'd':
				memcpy(p.devname, optarg, sizeof(p.devname));
				p.devname[sizeof(p.devname) - 1] = '\0';
				break;
			case 'v':
				p.carp_vhid = atoi(optarg);
				break;
			case 'k':
				if (strlen(optarg) != sizeof(p.carp_key))
				{
					fprintf(stderr, "Wrong key length. Must be %lu.\n", sizeof(p.carp_key));
					return -1;
				}
				memcpy(p.carp_key, optarg, sizeof(p.carp_key));
				break;
			case 'p':
				if (strlen(optarg) != sizeof(p.carp_pad))
				{
					fprintf(stderr, "Wrong pad length. Must be %lu.\n", sizeof(p.carp_pad));
					return -1;
				}
				memcpy(p.carp_pad, optarg, sizeof(p.carp_pad));
				break;
			case 'S':
				p.state = atoi(optarg);
				break;
			case 'h':
			default:
				need_change = 0;
				usage(argv[0]);
				return -1;
		}
	}

	if (!need_change)
	{
		usage(argv[0]);
		return -1;
	}

	ifr.ifr_ifru.ifru_data = (void *)&p;

	err = ioctl(s, SIOC_SETCARPPARAMS, &ifr);
	if (err == -1)
	{
		fprintf(stderr, "Failed to call ioctl: [%d] %s.\n",
				errno, strerror(errno));
		close(s);
		return -1;
	}

	close(s);

	return 0;
}
