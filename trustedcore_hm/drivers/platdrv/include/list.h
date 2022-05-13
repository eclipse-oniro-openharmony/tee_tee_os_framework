/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Linked list definitions
 * Create: 2019-05-18
 */

#ifndef LIBUTILS_LIST_H
#define LIBUTILS_LIST_H

#include <stdbool.h>
#include <stddef.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef container_of
#define container_of(p, type, element)                 \
    ({                                                 \
        type *q = (void *)p - offsetof(type, element); \
        q;                                             \
    })
#endif

#define LIST_HEAD_INIT(list)    { \
        .next = &(list),          \
        .prev = &(list),          \
    }

#define list_for_each(pos, list_head)  \
    for ((pos) = list_next(list_head); \
         !list_end(list_head, pos);    \
         (pos) = list_next(pos))

#define list_for_each_safe(pos, next, list_head)                \
    for ((pos) = list_next(list_head), (next) = list_next(pos); \
         !list_end(list_head, pos);                             \
         (pos) = (next), (next) = list_next(pos))

#define list_for_each_prev(pos, list_head) \
    for ((pos) = list_prev(list_head);     \
         !list_end(list_head, pos);        \
         (pos) = list_prev(pos))

#define list_first_entry(l, type, element)    ({ \
        struct list_head *first;                 \
        first = list_next(l);                    \
        container_of(first, type, element);      \
    })

#define list_entry(pos, type, element)    ({ \
        container_of(pos, type, element);    \
    })

struct list_head {
    struct list_head *next;
    struct list_head *prev;
};

static inline bool list_end(const struct list_head *head, const struct list_head *pos)
{
    return (pos == head);
}

static inline void init_list_head(struct list_head *list)
{
    list->prev = list;
    list->next = list;
}

static inline struct list_head *list_next(const struct list_head *list_head)
{
    if (list_head == NULL)
        return NULL;

    return list_head->next;
}

static inline struct list_head *list_prev(const struct list_head *list_head)
{
    if (list_head == NULL)
        return NULL;

    return list_head->prev;
}

static inline bool list_empty(const struct list_head *list_head)
{
    return (list_head->next == list_head);
}

static inline void list_del(struct list_head *list_item)
{
    struct list_head *next = list_item->next;
    struct list_head *prev = list_item->prev;

    next->prev = prev;
    prev->next = next;

    list_item->next = list_item;
    list_item->prev = list_item;
}

static inline void list_add_tail(struct list_head *list_item, struct list_head *list_head)
{
    struct list_head *prev = list_head->prev;

    list_item->prev = prev;
    list_item->next = list_head;

    prev->next      = list_item;
    list_head->prev = list_item;
}

#endif
