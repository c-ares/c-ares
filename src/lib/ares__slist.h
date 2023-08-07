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
#ifndef __ARES__SLIST_H
#define __ARES__SLIST_H

struct ares__slist;
typedef struct ares__slist ares__slist_t;

struct ares__slist_node;
typedef struct ares__slist_node ares__slist_node_t;

typedef void (*ares__slist_destructor_t)(void *data);
typedef int (*ares__slist_cmp_t)(const void *data1, const void *data2);

ares__slist_t *ares__slist_create(ares_rand_state *rand_state,
	                              ares__slist_cmp_t cmp,
	                              ares__slist_destructor_t destruct);
void ares__slist_replace_destructor(ares__slist_t *list,
	                                ares__slist_destructor_t destruct);
ares__slist_node_t *ares__slist_insert(ares__slist_t *list, void *val);
ares__slist_node_t *ares__slist_node_first(ares__slist_t *list);
ares__slist_node_t *ares__slist_node_last(ares__slist_t *list);
ares__slist_node_t *ares__slist_node_next(ares__slist_node_t *node);
ares__slist_node_t *ares__slist_node_prev(ares__slist_node_t *node);
ares__slist_node_t *ares__slist_node_find(ares__slist_t *list, const void *val);
void *ares__slist_node_val(ares__slist_node_t *node);
size_t ares__slist_len(ares__slist_t *list);
ares__slist_t *ares__llist_node_parent(ares__slist_node_t *node);
void *ares__slist_first_val(ares__slist_t *list);
void *ares__slist_last_val(ares__slist_t *list);
void *ares__slist_node_claim(ares__slist_node_t *node);
void ares__slist_node_replace(ares__slist_node_t *node, void *val);
void ares__slist_node_destroy(ares__slist_node_t *node);
void ares__slist_destroy(ares__slist_t *list);

#endif /* __ARES__SLIST_H */
