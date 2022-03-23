/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2012-2015. All rights reserved.
 * foss@huawei.com
 *
 * If distributed as part of the Linux kernel, the following license terms
 * apply:
 *
 * * This program is free software; you can redistribute it and/or modify
 * * it under the terms of the GNU General Public License version 2 and
 * * only version 2 as published by the Free Software Foundation.
 * *
 * * This program is distributed in the hope that it will be useful,
 * * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * * GNU General Public License for more details.
 * *
 * * You should have received a copy of the GNU General Public License
 * * along with this program; if not, write to the Free Software
 * * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA
 *
 * Otherwise, the following license terms apply:
 *
 * * Redistribution and use in source and binary forms, with or without
 * * modification, are permitted provided that the following conditions
 * * are met:
 * * 1) Redistributions of source code must retain the above copyright
 * *    notice, this list of conditions and the following disclaimer.
 * * 2) Redistributions in binary form must reproduce the above copyright
 * *    notice, this list of conditions and the following disclaimer in the
 * *    documentation and/or other materials provided with the distribution.
 * * 3) Neither the name of Huawei nor the names of its contributors may
 * *    be used to endorse or promote products derived from this software
 * *    without specific prior written permission.
 *
 * * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */
#ifndef _OSL_LIST_H
#define _OSL_LIST_H

/* 从内存角度考虑，用list不如用数组 ?? */

#define inline __inline__
#define OSL_INLINE __inline__
#ifndef typeof
#define typeof __typeof__
#endif

struct hi_list {
    struct hi_list *next;
    struct hi_list *prev;
};

#define HILIST_MEM_INIT(object) { &(object), &(object) }

#define HILIST_DEF(object) struct hi_list object = HILIST_MEM_INIT(object)


#define HILIST_INIT(head) \
    do { \
        (head)->prev = (head); \
        (head)->next = (head); \
    } while (0)


static OSL_INLINE void hilist_insert(struct hi_list *new_node, struct hi_list *prev_node, struct hi_list *next_node)
{
    next_node->prev = new_node;
    new_node->next = next_node;
    new_node->prev = prev_node;
    prev_node->next = new_node;
}

static OSL_INLINE void hilist_insert_head(struct hi_list *new_node, struct hi_list *head)
{
	hilist_insert(new_node, head, head->next);
}

static OSL_INLINE void hilist_insert_tail(struct hi_list *new_node, struct hi_list *head)
{
	hilist_insert(new_node, head->prev, head);
}

static OSL_INLINE void hilist_remove(struct hi_list *node)
{
    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->prev = (struct hi_list *)NULL;
    node->next = (struct hi_list *)NULL;
}

static OSL_INLINE void hilist_remove_init(struct hi_list *node)
{
    node->next->prev = node->prev;
    node->prev->next = node->next;
    HILIST_INIT(node);
}

static OSL_INLINE void hilist_move_tail(struct hi_list *node, struct hi_list *head)
{
    node->next->prev = node->prev;
    node->prev->next = node->next;
    hilist_insert_tail(node, head);
}

static OSL_INLINE int hilist_empty(const struct hi_list *list)
{
    return list->next == list;
}

#undef stru_member_offset
#ifdef __compiler_offsetof
#define stru_member_offset(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define stru_member_offset(TYPE, MEMBER) ((uintptr_t) & ((TYPE *)0)->MEMBER)
#endif

#define stru_member_addr(pointer, str_type, member) ((str_type *)((char *)(pointer)-stru_member_offset(str_type, member)))

#define hilist_loop(position, head) for (position = (head)->next; position != (head); position = position->next)

#define hilist_loop_safe(position, node, head) \
	for (position = (head)->next, node = position->next; position != (head); \
		position = node, node = position->next)

#define hilist_get_node(ptr, type, member) stru_member_addr(ptr, type, member)

#define hilist_get_first_node(ptr, type, member) hilist_get_node((ptr)->next, type, member)
#define hilist_loop_node(position, head, member)                                                                \
    for (/*lint -epn -epp*/ position = hilist_get_node((head)->next, typeof(*position) /*lint +rw( typeof )*/, member); \
	     (position != NULL) && (&position->member != (head)); 	\
	     position = hilist_get_node(position->member.next, typeof(*position), member))

#define hilist_loop_node_safe(position, node, head, member)			\
    for (position = hilist_get_node(/*lint -epn -epp*/ (head)->next, typeof(*position), member), \
		node = hilist_get_node(position->member.next, typeof(*position), member);	\
	     (position != NULL) && (&position->member != (head)); 					\
	     position = node, node = hilist_get_node(node->member.next, typeof(*node), member))
#endif
