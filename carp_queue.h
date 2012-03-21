/*
 * 	carp_queue.h
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

#ifndef __CARP_QUEUE_H
#define __CARP_QUEUE_H

#include <linux/workqueue.h>

#include <asm/atomic.h>

enum carp_queue_number {MASTER_QUEUE = 0, BACKUP_QUEUE};

struct __carp_master_task
{
	atomic_t	refcnt;
	u32		id;

	void 		(* callback)(void *);
	void		*data;

	void		*priv;
};

struct carp_master_task
{
	struct list_head		entry;
	struct __carp_master_task	*task;

	struct work_struct		work;
};

int carp_init_queues(void);
void carp_flush_queue(int);
void carp_fini_queues(void);
void carp_call_queue(int);

int carp_add_task(struct __carp_master_task *, int);
void carp_del_task(struct __carp_master_task *, int);

#endif /* __CARP_QUEUE_H */
