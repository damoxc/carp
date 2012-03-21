/*
 * 	carp_queue.c
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

#include <linux/workqueue.h>
#include <asm/spinlock.h>

#include "carp.h"
#include "carp_log.h"
#include "carp_queue.h"

static DEFINE_SPINLOCK(carp_queue_lock);
static struct workqueue_struct *carp_queue[2];
static struct list_head carp_works[2];
static int carp_work_counter;

static void carp_queue_wrapper(struct work_struct *ws)
{
	struct carp_master_task *t = container_of(ws, struct carp_master_task, work);

	atomic_inc(&t->task->refcnt);
	t->task->callback(t->task->data);
	atomic_dec(&t->task->refcnt);
}

struct carp_master_task *carp_alloc_task(struct __carp_master_task *t)
{
	struct carp_master_task *newt;

	newt = kmalloc(sizeof(struct carp_master_task), GFP_KERNEL);
	if (!newt)
	{
		log("Failed to create new CARP master task.\n");
		return NULL;
	}

	memset(newt, 0, sizeof(struct carp_master_task));

	atomic_set(&t->refcnt, 1);
	newt->task = t;
	newt->task->id = carp_work_counter++;

	INIT_WORK(&newt->work, &carp_queue_wrapper);

	return newt;
}

static void carp_free_task(struct carp_master_task *t)
{
	cancel_delayed_work(&t->work);

	while(atomic_read(&t->task->refcnt))
		schedule_timeout(10);

	kfree(t);
}

int carp_add_task(struct __carp_master_task *mt, int num)
{
	struct carp_master_task *newt;

	if (num != MASTER_QUEUE && num != BACKUP_QUEUE)
		return -EINVAL;

	newt = carp_alloc_task(mt);
	if (!newt)
		return -ENOMEM;

	list_add_tail(&newt->entry, &carp_works[num]);
	spin_unlock(&carp_queue_lock);

	return 0;
}

void carp_del_task(struct __carp_master_task *mt, int num)
{
	struct list_head *ent, *n;
	struct carp_master_task *t = NULL;
	int found = 0;

	if (num != MASTER_QUEUE && num != BACKUP_QUEUE)
		return;

	spin_lock(&carp_queue_lock);
	list_for_each_safe(ent, n, &carp_works[num])
	{
		t = list_entry(ent, struct carp_master_task, entry);

		if (t->task->id == mt->id) {
			list_del(&t->entry);
			found = 1;
			break;
		}
	}
	spin_unlock(&carp_queue_lock);

	if (found)
	{
		atomic_dec(&t->task->refcnt);
		carp_free_task(t);
	}
}

void carp_call_queue(int num)
{
	struct list_head *ent, *n;
	struct carp_master_task *t;

	if (num != MASTER_QUEUE && num != BACKUP_QUEUE)
		return;

	spin_lock(&carp_queue_lock);
	list_for_each_safe(ent, n, &carp_works[num])
	{
		t = list_entry(ent, struct carp_master_task, entry);
		queue_work(carp_queue[num], &t->work);
	}
	spin_unlock(&carp_queue_lock);
}

int carp_init_queues(void)
{
	int i;

	for (i=0; i<2; ++i)
		INIT_LIST_HEAD(&carp_works[i]);

	carp_queue[MASTER_QUEUE] = create_workqueue("CARP_m");
	if (!carp_queue[MASTER_QUEUE])
	{
		log("Failed to create master CARP queue.\n");
		return -1;
	}

	carp_queue[BACKUP_QUEUE] = create_workqueue("CARP_b");
	if (!carp_queue[BACKUP_QUEUE])
	{
		destroy_workqueue(carp_queue[MASTER_QUEUE]);
		log("Failed to create backup CARP queue.\n");
		return -1;
	}

	return 0;
}

void carp_flush_queue(int num)
{
	if (num != MASTER_QUEUE && num != BACKUP_QUEUE)
		return;

	flush_workqueue(carp_queue[num]);
}

void carp_fini_queues(void)
{
	carp_flush_queue(MASTER_QUEUE);
	destroy_workqueue(carp_queue[MASTER_QUEUE]);
	carp_flush_queue(BACKUP_QUEUE);
	destroy_workqueue(carp_queue[BACKUP_QUEUE]);
}

