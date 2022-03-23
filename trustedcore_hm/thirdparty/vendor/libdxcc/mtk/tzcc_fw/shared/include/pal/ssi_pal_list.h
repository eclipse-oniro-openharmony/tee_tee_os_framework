/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_LIST_H
#define _SSI_PAL_LIST_H

typedef struct SaSi_PalListItem {
    struct SaSi_PalListItem *prev;
    struct SaSi_PalListItem *next;
} SaSi_PalListItem_s;

/* !
 * Initializes a list. Prev/Next points to the same head object.
 *
 * \param head The head of the list.
 */
static inline void SaSi_PalListInit(SaSi_PalListItem_s *head)
{
    head->prev = head;
    head->next = head;
}

/* !
 * Add a new list item after head of list.
 *
 * \param new New entry to be added
 * \param head List head to add it after
 */
static inline void SaSi_PalListAdd(SaSi_PalListItem_s *new, SaSi_PalListItem_s *head)
{
    SaSi_PalListItem_s *next = head->next;

    next->prev = new;
    new->next  = next;
    new->prev  = head;
    head->next = new;
}

/* !
 * Add a new list item after head of list.
 *
 * \param new New entry to be added
 * \param head List head to add it after
 */
static inline void SaSi_PalListAddTail(SaSi_PalListItem_s *new, SaSi_PalListItem_s *head)
{
    SaSi_PalListItem_s *prev = head->prev;

    prev->next = new;
    new->next  = head;
    new->prev  = prev;
    head->prev = new;
}

/* !
 * Deletes entry from list.
 *
 * \param item The item to delete from the list.
 */
static inline void SaSi_PalListDel(SaSi_PalListItem_s *item)
{
    SaSi_PalListItem_s *prev = item->prev;
    SaSi_PalListItem_s *next = item->next;

    prev->next = next;
    next->prev = prev;

    item->next = item;
    item->prev = item;
}

/* !
 * Checks whether a list is empty.
 *
 * \param head The list's head
 *
 * \return int True if empty list, False otherwise.
 */
static inline int SaSi_PalIsListEmpty(const SaSi_PalListItem_s *head)
{
    return (head->next == head);
}

#endif
