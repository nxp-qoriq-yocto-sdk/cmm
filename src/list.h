/*
*   Copyright (c) 2016 Freescale Semiconductor, Inc. All rights reserved.
*   Copyright 2016 NXP
*
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
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*
*/


#ifndef __LIST_H
#define __LIST_H

#include <assert.h>

struct list_head {
	struct list_head *prev;
	struct list_head *next;
};

static inline void list_head_init(struct list_head *head)
{
	head->prev = head;
	head->next = head;
}

static inline void list_add(struct list_head *head, struct list_head *entry)
{
	assert((!entry->next) && (!entry->prev));

	entry->next = head->next;
	entry->next->prev = entry;

	head->next = entry;
	entry->prev = head;
}

static inline void list_del(struct list_head *entry)
{
	entry->prev->next = entry->next;
	entry->next->prev = entry->prev;
	entry->prev = NULL;
	entry->next = NULL;
}

#define list_empty(head)	((head)->next == (head))

#define offset_of(type, member) ((unsigned long)&(((type *)0)->member))
#define container_of(entry, type, member) ((type *)((unsigned char *)(entry) - offset_of(type, member)))

#define list_first(head)	((head)->next)
#define list_last(head)		((head)->prev)
#define list_next(entry)	((entry)->next)

#endif
