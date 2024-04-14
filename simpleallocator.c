#include <sys/mman.h>
#include <stddef.h>
#include <stdio.h>
#include "util.h"

/* 
 * This is a very simple allocator for the purposes of explaining
 * heap corruption exploitation strategies.
 *
 * This allocator is not thread-safe.
 *
 * (c) 2024 Dimitrios Glynos (@dfunc on Twitter)
 * See LICENSE file for license information.
 */

/* 
 = memory layout ========================================================

     [  ...  ]   mmap-ed zone
     ^
     |                                                   
   (next)               (next)-----
     |                  |         |
     |                  |         v
   [sa_zone_t|sa_freelist_t| data |sa_freelist_t|data|...]   mmap-ed zone
    |    |   ^  | |        ^                              ^
    |    |   |  | |        |                              |
    |    |   |  | --(data)--                              |
    |    |   |  |                                         |
    |    |   |  |                                         |
    |    |   |  -----------<-len->                        |
 (start)------                                            |
         |                                                |
         |                                                |
         (end)---------------------------------------------
*/

#define INITIAL_SIZE (100 * 1024)

typedef struct _sa_zone_t {
	void *start;
	void *end;
	struct _sa_zone_t *next;
} sa_zone_t;

typedef struct _sa_freelist_t {
	struct _sa_freelist_t *next;
	size_t len;
	void *data;
} sa_freelist_t;

static sa_zone_t *zones = NULL;
static size_t cur_zone_sz;
static sa_freelist_t *freelist;

static int within_same_zone(void *one, void *other) {
	sa_zone_t *z;
	for (z=zones; z; z=z->next) {
		if ((z->start <= one) && (one < z->end) &&
		    (z->start <= other) && (other < z->end))
		{
			return 1;
		}
	}
	return 0;
}

static int on_freelist(void *p, sa_freelist_t **prev) {
	sa_freelist_t *q;

	if (!freelist) {
		return 0;
	}

	for (*prev = NULL, q = freelist; q; *prev = q, q=q->next) {
		if (q == p) {
			return 1;
		}
	}

	return 0;
}

void sa_print_freelist(void) {
	sa_freelist_t *p;

	if (!freelist) {
		return;
	}

	for(p=freelist; p; p = p->next) {
		DPRINTF("freelist item %p data %p len %lu next %p\n",
			p, p->data, p->len, p->next);
	}
}

static int grow_avail_mem(size_t region) {
	sa_zone_t *zone;
	sa_freelist_t *free_node;

	zone = mmap(NULL, region, 
	            PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (zone == MAP_FAILED) {
		return 0;
	}

	cur_zone_sz = region;

	zone->start = (void *) zone + sizeof(sa_zone_t);
	zone->end = (void *) zone + cur_zone_sz;
	zone->next = zones;
	zones = zone;

	free_node = zone->start;
	free_node->data = zone->start + sizeof(sa_freelist_t);
	free_node->len = cur_zone_sz - sizeof(sa_zone_t) - 
		         sizeof(sa_freelist_t);
	free_node->next = freelist;
	freelist = free_node;

	DPRINTF("new zone on freelist %p data %p len %lu\n", free_node, free_node->data, free_node->len);
	return 1;
}

static void use(sa_freelist_t *prev, sa_freelist_t *node, size_t len) {
	sa_freelist_t *new;

	if ((node->len - len) >= (sizeof(sa_freelist_t) + 1)) {
		new = (sa_freelist_t *) (node->data + len);
		new->data = (void *) new + sizeof(sa_freelist_t);
		new->len = node->len - len - sizeof(sa_freelist_t);
		new->next = node->next;
		DPRINTF("split off %p len %lu\n", new, new->len);

		if (!prev) {
			freelist = new;
		} else {
			prev->next = new;
		}
		sa_print_freelist();
		node->len = len;
		node->next = NULL;
	} else {
		// won't reserve exactly len, because it's simpler this way
		if (!prev) {
			freelist = node->next;
		} else {
			prev->next = node->next;
		}
		sa_print_freelist();
		node->next = NULL;
	}
}

static sa_freelist_t *find_right(size_t len, sa_freelist_t **prev) {
	sa_freelist_t *first_good, *p;

	*prev = NULL;
	first_good = NULL;

	for(p = freelist; p; *prev = p, p = p->next) 
	{
		if (p->len >= len) {
			first_good = p;
			DPRINTF("found spot for %lu, %p len %lu\n",
					len, first_good, p->len);
			break;
		}
	}
	return first_good;
}

static void merge(sa_freelist_t *node1, 
		  sa_freelist_t *node2, 
		  sa_freelist_t *node2_prev) 
{
	node1->len += node2->len + sizeof(sa_freelist_t);
	if (node2_prev) {
		node2_prev->next = node2->next;
	} else {
		freelist = node2->next;
	}
	node2->next = NULL;
}

static void do_freelist_merge(void) {
	sa_freelist_t *leader, *p;
	sa_freelist_t *prev_next;

	leader = freelist;

	while(leader) {
		int done = 0;
		p = leader;
		while(!done) {
			sa_freelist_t *next_node = p->data + p->len;

 		     /* WARNING: next_node may now point to unallocated mem */

			if (within_same_zone(leader, next_node) &&
			    on_freelist(next_node, &prev_next)) 
			{
				p = next_node;
				DPRINTF("merging %p (%lu) %p (%lu)\n", 
						leader, leader->len,
						next_node, next_node->len);
				merge(leader, next_node, prev_next);
			} else {
				done = 1;
			}
		}
		leader = leader->next;
	}
}

void *sa_alloc(size_t region) {
	sa_freelist_t *node, *prev;
	int merged, realloced;

	merged = 0;
	realloced = 0;

	if (region == 0) return NULL;
	
	if (!zones) {
		/* lazy zone init, called on first allocation */
		if (!grow_avail_mem(INITIAL_SIZE)) {
			return NULL;
		}
	}
again:
	node = find_right(region, &prev);
	if (node) {
		use(prev, node, region);
	} else if (!merged) {
		do_freelist_merge();
		merged = 1;
		goto again;
	} else if (merged && !realloced) {
		size_t want;
		if (region > (2 * cur_zone_sz)) {
			want = (region + 0x100000) & ~0xfffff; 
		} else {
			want = 2 * cur_zone_sz;
		}

		if (!grow_avail_mem(want)) {
			DPRINTF("could not grow mem by %lu\n", want);
			return NULL;
		}
		cur_zone_sz = want;
		realloced = 1;
		goto again;
	} else {
		DPRINTF("malloc failed for region %lu\n", region);
		return NULL;
	}

	return node->data;
}

void sa_free(void *ptr) {
	sa_freelist_t *p;

	if (!ptr) {
		return;
	}

	p = ((void *) ptr - sizeof(sa_freelist_t));
	p->next = freelist;
	freelist = p;

	DPRINTF("free %p, placed first on freelist\n", p);
	sa_print_freelist();
}

