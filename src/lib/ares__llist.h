/* Copyright (C) 2023 by Brad House
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef __ARES__LLIST_H__
#define __ARES__LLIST_H__

struct ares__llist;
typedef struct ares__llist ares__llist_t;

struct ares__llist_node;
typedef struct ares__llist_node ares__llist_node_t;

typedef void (*ares__llist_destructor_t)(void *data);

ares__llist_t *ares__llist_create(ares__llist_destructor_t destruct);
ares__llist_node_t *ares__llist_insert_first(ares__llist_t *list, void *val);
ares__llist_node_t *ares__llist_insert_last(ares__llist_t *list, void *val);
ares__llist_node_t *ares__llist_insert_before(ares__llist_node_t *node, void *val);
ares__llist_node_t *ares__llist_insert_after(ares__llist_node_t *node, void *val);
ares__llist_node_t *ares__llist_first(ares__llist_t *list);
ares__llist_node_t *ares__llist_last(ares__llist_t *list);
ares__llist_node_t *ares__llist_node_next(ares__llist_node_t *node);
ares__llist_node_t *ares__llist_node_prev(ares__llist_node_t *node);
void *ares__llist_val(ares__llist_node_t *node);
size_t ares__llist_len(ares__llist_t *list);
ares__llist_t *ares__llist_node_parent(ares__llist_node_t *node);
void *ares__llist_first_val(ares__llist_t *list);
void *ares__llist_last_val(ares__llist_t *list);
void *ares__llist_node_claim(ares__llist_node_t *node);
void ares__llist_node_destroy(ares__llist_node_t *node);
void ares__list_destroy(ares__llist_t *list);

#endif
