/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Provide a header file for the list operation
 * Author: Hisilicon hisecurity team
 * Create: 2019-08-12
 */

#ifndef __DRV_KLAD_LIST_H__
#define __DRV_KLAD_LIST_H__

#include "hi_type_dev.h"

struct list_head {
    struct list_head *next, *prev;
};

struct hlist_head {
    struct hlist_node *first;
};

struct hlist_node {
    struct hlist_node *next, **pprev;
};

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({          \
        const typeof(((type *)0)->member) *__mptr = (ptr);    \
        (type *)((hi_char *)__mptr - offsetof(type, member));})

#define list_head_init(name) { &(name), &(name) }

#define list_head(name) \
    struct list_head name = list_head_init(name)

static inline void init_list_head(struct list_head *list)
{
    if (list == HI_NULL) {
        return;
    }
    list->next = list;
    list->prev = list;
}

static inline void __list_add(struct list_head *new,
                              struct list_head *prev,
                              struct list_head *next)
{
    if (new == HI_NULL || prev == HI_NULL || next == HI_NULL) {
        return;
    }
    next->prev = new;
    new->next = next;
    new->prev = prev;
    prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
    if (new == HI_NULL || head == HI_NULL) {
        return;
    }
    __list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
    if (new == HI_NULL || head == HI_NULL || head->prev == HI_NULL) {
        return;
    }
    __list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head *prev, struct list_head *next)
{
    if (prev == HI_NULL || next == HI_NULL) {
        return;
    }
    next->prev = prev;
    prev->next = next;
}

static inline void __list_del_entry(struct list_head *entry)
{
    if (entry == HI_NULL) {
        return;
    }
    __list_del(entry->prev, entry->next);
}

static inline void list_del(struct list_head *entry)
{
    if (entry == HI_NULL || entry->prev == HI_NULL || entry->next == HI_NULL) {
        return;
    }
    __list_del(entry->prev, entry->next);
    entry->next = NULL;
    entry->prev = NULL;
}

static inline void list_replace(struct list_head *old,
                                struct list_head *new)
{
    if (old == HI_NULL || new == HI_NULL) {
        return;
    }
    new->next = old->next;
    new->next->prev = new;
    new->prev = old->prev;
    new->prev->next = new;
}

static inline void list_replace_init(struct list_head *old,
                                     struct list_head *new)
{
    if (new == HI_NULL || old == HI_NULL) {
        return;
    }
    list_replace(old, new);
    init_list_head(old);
}

static inline void list_del_init(struct list_head *entry)
{
    if (entry == HI_NULL) {
        return;
    }
    __list_del_entry(entry);
    init_list_head(entry);
}

static inline void list_move(struct list_head *list, struct list_head *head)
{
    if (list == HI_NULL || head == HI_NULL) {
        return;
    }
    __list_del_entry(list);
    list_add(list, head);
}

static inline void list_move_tail(struct list_head *list,
                                  struct list_head *head)
{
    if (list == HI_NULL || head == HI_NULL) {
        return;
    }
    __list_del_entry(list);
    list_add_tail(list, head);
}

static inline hi_s32 list_is_last(const struct list_head *list,
                                  const struct list_head *head)
{
    if (list == HI_NULL || head == HI_NULL) {
        return HI_FALSE;
    }
    return list->next == head;
}

static inline hi_s32 list_empty(const struct list_head *head)
{
    if (head == HI_NULL) {
        return HI_FALSE;
    }
    return head->next == head;
}

static inline hi_s32 list_empty_careful(const struct list_head *head)
{
    if (head == HI_NULL) {
        return HI_FALSE;
    }
    struct list_head *next = head->next;
    return (next == head) && (next == head->prev);
}

static inline void list_rotate_left(struct list_head *head)
{
    struct list_head *first = NULL;

    if (head == HI_NULL) {
        return;
    }
    if (!list_empty(head)) {
        first = head->next;
        list_move_tail(first, head);
    }
}

static inline hi_s32 list_is_singular(const struct list_head *head)
{
    if (head == HI_NULL) {
        return HI_FALSE;
    }
    return !list_empty(head) && (head->next == head->prev);
}

static inline void __list_splice(const struct list_head *list,
                                 struct list_head *prev,
                                 struct list_head *next)
{
    if (list == HI_NULL || prev == HI_NULL || next == HI_NULL) {
        return;
    }

    list->next->prev = prev;
    prev->next = list->next;

    list->prev->next = next;
    next->prev = list->prev;
}

static inline void list_splice(const struct list_head *list,
                               struct list_head *head)
{
    if (list == HI_NULL || head == HI_NULL) {
        return;
    }
    if (!list_empty(list)) {
        __list_splice(list, head, head->next);
    }
}

static inline void list_splice_tail(struct list_head *list,
                                    struct list_head *head)
{
    if (list == HI_NULL || head == HI_NULL) {
        return;
    }
    if (!list_empty(list)) {
        __list_splice(list, head->prev, head);
    }
}

static inline void list_splice_init(struct list_head *list,
                                    struct list_head *head)
{
    if (list == HI_NULL || head == HI_NULL) {
        return;
    }
    if (!list_empty(list)) {
        __list_splice(list, head, head->next);
        init_list_head(list);
    }
}

static inline void list_splice_tail_init(struct list_head *list, struct list_head *head)
{
    if (list == HI_NULL || head == HI_NULL) {
        return;
    }
    if (!list_empty(list)) {
        __list_splice(list, head->prev, head);
        init_list_head(list);
    }
}

#define list_entry(ptr, type, member) \
    container_of(ptr, type, member)

#define list_first_entry(ptr, type, member) \
    list_entry((ptr)->next, type, member)

#define list_last_entry(ptr, type, member) \
    list_entry((ptr)->prev, type, member)

#define list_first_entry_or_null(ptr, type, member) \
    (!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)

#define list_next_entry(pos, member) \
    list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_prev_entry(pos, member) \
    list_entry((pos)->member.prev, typeof(*(pos)), member)

#define list_for_each(pos, head) \
    for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

#define list_for_each_prev(pos, head) \
    for ((pos) = (head)->prev; (pos) != (head); (pos) = (pos)->prev)

#define list_for_each_safe(pos, n, head) \
    for ((pos) = (head)->next, (n) = (pos)->next; (pos) != (head); \
         (pos) = (n), (n) = (pos)->next)

#define list_for_each_prev_safe(pos, n, head) \
    for ((pos) = (head)->prev, (n) = (pos)->prev; \
         (pos) != (head); \
         (pos) = (n), (n) = (pos)->prev)

#define list_for_each_entry(pos, head, member)              \
    for ((pos) = list_first_entry(head, typeof(*(pos)), member);    \
         &(pos)->member != (head);                    \
         (pos) = list_next_entry((pos), member))

#define list_for_each_entry_reverse(pos, head, member)          \
    for ((pos) = list_last_entry(head, typeof(*(pos)), member);     \
         &(pos)->member != (head);                    \
         (pos) = list_prev_entry(pos, member))

#define list_prepare_entry(pos, head, member) \
    ((pos) ? : list_entry(head, typeof(*(pos)), member))

#define list_for_each_entry_continue(pos, head, member)         \
    for ((pos) = list_next_entry(pos, member);        \
         &(pos)->member != (head);                    \
         (pos) = list_next_entry(pos, member))

#define list_for_each_entry_continue_reverse(pos, head, member)     \
    for ((pos) = list_prev_entry(pos, member);        \
         &(pos)->member != (head);                    \
         (pos) = list_prev_entry(pos, member))

#define list_for_each_entry_from(pos, head, member) \
    for (; &(pos)->member != (head);                  \
         (pos) = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)          \
    for ((pos) = list_first_entry(head, typeof(*(pos)), member),    \
         (n) = list_next_entry(pos, member);          \
         &(pos)->member != (head);                    \
         (pos) = (n), (n) = list_next_entry(n, member))

#define list_for_each_entry_safe_continue(pos, n, head, member)         \
    for ((pos) = list_next_entry(pos, member),            \
         (n) = list_next_entry(pos, member);              \
         &(pos)->member != (head);                        \
         (pos) = (n), (n) = list_next_entry(n, member))

#define list_for_each_entry_safe_from(pos, n, head, member)             \
    for ((n) = list_next_entry(pos, member);              \
         &(pos)->member != (head);                        \
         (pos) = (n), (n) = list_next_entry(n, member))

#define list_for_each_entry_safe_reverse(pos, n, head, member)      \
    for ((pos) = list_last_entry(head, typeof(*(pos)), member),     \
         (n) = list_prev_entry(pos, member);          \
         &(pos)->member != (head);                    \
         (pos) = (n), (n) = list_prev_entry(n, member))

#define list_safe_reset_next(pos, n, member)                \
    (n) = list_next_entry(pos, member)

#define HLIST_HEAD_INIT {.first = NULL}
#define hlist_head(name) struct hlist_head name = {.first = NULL}
#define init_hlist_head(ptr) ((ptr)->first = NULL)
static inline void init_hlist_node(struct hlist_node *h)
{
    if (h == HI_NULL) {
        return;
    }
    h->next = NULL;
    h->pprev = NULL;
}

static inline hi_s32 hlist_unhashed(const struct hlist_node *h)
{
    if (h == HI_NULL) {
        return HI_FALSE;
    }
    return !h->pprev;
}

static inline hi_s32 hlist_empty(const struct hlist_head *h)
{
    if (h == HI_NULL) {
        return HI_FALSE;
    }
    return !h->first;
}

static inline void __hlist_del(struct hlist_node *n)
{
    if (n == HI_NULL) {
        return;
    }
    struct hlist_node **pprev = n->pprev;
    *pprev = n->next;
    if (n->next != HI_NULL) {
        n->next->pprev = pprev;
    }
}

static inline void hlist_del(struct hlist_node *n)
{
    if (n == HI_NULL) {
        return;
    }
    __hlist_del(n);
    n->next = NULL;
    n->pprev = NULL;
}

static inline void hlist_del_init(struct hlist_node *n)
{
    if (n == HI_NULL) {
        return;
    }
    if (!hlist_unhashed(n)) {
        __hlist_del(n);
        init_hlist_node(n);
    }
}

/* next must be != NULL */
static inline void hlist_add_before(struct hlist_node *n,
                                    struct hlist_node *next)
{
    if (n == HI_NULL || next == HI_NULL) {
        return;
    }
    n->pprev = next->pprev;
    n->next = next;
    next->pprev = &n->next;
    *(n->pprev) = n;
}

static inline void hlist_add_fake(struct hlist_node *n)
{
    if (n == HI_NULL) {
        return;
    }
    n->pprev = &n->next;
}

static inline void hlist_move_list(struct hlist_head *old,
                                   struct hlist_head *new)
{
    if (new == HI_NULL || old == HI_NULL) {
        return;
    }
    new->first = old->first;
    if (new->first != HI_NULL) {
        new->first->pprev = &new->first;
    }
    old->first = NULL;
}

#define hlist_entry(ptr, type, member) container_of(ptr, type, member)

#define hlist_for_each(pos, head) \
    for ((pos) = (head)->first; pos ; (pos) = (pos)->next)

#define hlist_for_each_safe(pos, n, head) \
    for ((pos) = (head)->first; (pos) && ({ (n) = (pos)->next; 1; }); \
         (pos) = (n))

#define hlist_entry_safe(ptr, type, member) \
    ({ typeof(ptr) ____ptr = (ptr); \
        ____ptr ? hlist_entry(____ptr, type, member) : NULL; \
    })

#define hlist_for_each_entry(pos, head, member)             \
    for ((pos) = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
         pos;                           \
         (pos) = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#define hlist_for_each_entry_continue(pos, member)          \
    for ((pos) = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member);\
         pos;                           \
         (pos) = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#define hlist_for_each_entry_from(pos, member)              \
    for (; pos;                         \
         (pos) = hlist_entry_safe((pos)->member.next, typeof(*(pos)), member))

#define hlist_for_each_entry_safe(pos, n, head, member)         \
    for ((pos) = hlist_entry_safe((head)->first, typeof(*(pos)), member);\
    (pos) && ({ (n) = (pos)->member.next; 1; });          \
         (pos) = hlist_entry_safe(n, typeof(*(pos)), member))

#endif
