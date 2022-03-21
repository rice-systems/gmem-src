/*-
 * 
 * This software was developed by Weixi Zhu <wxzhu@rice.edu>
 * for gmem project.
 *
 * GMEM is a generic memory management interface for CPU and devices
 * It currently only supports x86_64 platforms.
 *
 */

#ifndef _GMEM_RB_TREE_H_
#define _GMEM_RB_TREE_H_

#include <sys/gmem.h>
#include <amd64/gmem/gmem_dev.h>
#include <amd64/gmem/gmem_uvas.h>

static int gmem_rb_cmp_entries(struct gmem_uvas_entry *a, struct gmem_uvas_entry *b)
{
	// copied from iommu code
	KASSERT(a->start <= a->end, ("inverted entry %p (%jx, %jx)",
	    a, (uintmax_t)a->start, (uintmax_t)a->end));
	KASSERT(b->start <= b->end, ("inverted entry %p (%jx, %jx)",
	    b, (uintmax_t)b->start, (uintmax_t)b->end));
	KASSERT(a->end <= b->start || b->end <= a->start ||
	    a->end == a->start || b->end == b->start,
	    ("overlapping entries %p (%jx, %jx) %p (%jx, %jx)",
	    a, (uintmax_t)a->start, (uintmax_t)a->end,
	    b, (uintmax_t)b->start, (uintmax_t)b->end));

	if (a->end < b->end)
		return (-1);
	else if (b->end < a->end)
		return (1);
	return (0);
}

static void
gmem_rb_augment_entry(struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_entry *child;
	vm_size_t free_down;

	free_down = 0;
	if ((child = RB_LEFT(entry, rb_entry)) != NULL) {
		free_down = MAX(free_down, child->free_down);
		free_down = MAX(free_down, entry->start - child->last);
		entry->first = child->first;
	} else
		entry->first = entry->start;
	
	if ((child = RB_RIGHT(entry, rb_entry)) != NULL) {
		free_down = MAX(free_down, child->free_down);
		free_down = MAX(free_down, child->first - entry->end);
		entry->last = child->last;
	} else
		entry->last = entry->end;
	entry->free_down = free_down;
}

RB_GENERATE(gmem_uvas_entries_tree, gmem_uvas_entry, rb_entry,
    gmem_rb_cmp_entries);

static bool
gmem_rb_insert(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_entry *found;

	found = RB_INSERT(gmem_uvas_entries_tree,
	    &uvas->rb_root, entry);
	return (found == NULL);
}

static void
gmem_rb_remove(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{

	RB_REMOVE(gmem_uvas_entries_tree, &uvas->rb_root, entry);
}

static void
gmem_rb_init(struct gmem_uvas *uvas)
{
	struct gmem_uvas_entry *begin, *end;

	begin = gmem_uvas_alloc_entry(uvas, GMEM_WAITOK);
	end = gmem_uvas_alloc_entry(uvas, GMEM_WAITOK);

	GMEM_UVAS_LOCK(uvas);
	KASSERT(RB_EMPTY(&uvas->rb_root),
	    ("non-empty entries %p", uvas));

	begin->start = 0;
	begin->end = GMEM_PAGE_SIZE;
	begin->flags = GMEM_UVAS_ENTRY_PLACE | GMEM_UVAS_ENTRY_UNMAPPED;
	gmem_rb_insert(uvas, begin);

	end->start = uvas->format.maxaddr;
	end->end = uvas->format.maxaddr;
	end->flags = GMEM_UVAS_ENTRY_PLACE | GMEM_UVAS_ENTRY_UNMAPPED;
	gmem_rb_insert(uvas, end);

	uvas->first_place = begin;
	uvas->last_place = end;
	// uvas->flags |= IOMMU_DOMAIN_GAS_INITED;
	GMEM_UVAS_UNLOCK(uvas);
}

static void
gmem_rb_destroy(struct gmem_uvas *uvas)
{
	struct gmem_uvas_entry *entry, *entry1;

	KASSERT(uvas->entries_cnt == 2,
	    ("uvas still in use %p", uvas));

	entry = RB_MIN(gmem_uvas_entries_tree, &uvas->rb_root);
	KASSERT(entry->start == 0, ("start entry start %p", uvas));
	KASSERT(entry->end == GMEM_PAGE_SIZE, ("start entry end %p", uvas));
	KASSERT(entry->flags ==
	    (GMEM_UVAS_ENTRY_PLACE | GMEM_UVAS_ENTRY_UNMAPPED),
	    ("start entry flags %p", uvas));
	RB_REMOVE(gmem_uvas_entries_tree, &uvas->rb_root, entry);
	gmem_uvas_free_entry(uvas, entry);

	entry = RB_MAX(gmem_uvas_entries_tree, &uvas->rb_root);
	KASSERT(entry->start == uvas->end, ("end entry start %p", uvas));
	KASSERT(entry->end == uvas->end, ("end entry end %p", uvas));
	KASSERT(entry->flags ==
	    (GMEM_UVAS_ENTRY_PLACE | GMEM_UVAS_ENTRY_UNMAPPED),
	    ("end entry flags %p", uvas));
	RB_REMOVE(gmem_uvas_entries_tree, &uvas->rb_root, entry);
	gmem_uvas_free_entry(uvas, entry);

	RB_FOREACH_SAFE(entry, gmem_uvas_entries_tree, &uvas->rb_root,
	    entry1) {
		KASSERT((entry->flags & GMEM_UVAS_ENTRY_RMRR) != 0,
		    ("non-RMRR entry left %p", uvas));
		RB_REMOVE(gmem_uvas_entries_tree, &uvas->rb_root,
		    entry);
		gmem_uvas_free_entry(uvas, entry);
	}
}

struct gmem_rb_match_args {
	struct gmem_uvas *uvas;
	vm_offset_t size;
	int offset;
	// const struct bus_dma_tag_common *common;
	u_int gas_flags;
	struct gmem_uvas_entry *entry;
};

/*
 * The interval [beg, end) is a free interval between two gmem_uvas_entries.
 * maxaddr is an upper bound on addresses that can be allocated. Try to
 * allocate space in the free interval, subject to the conditions expressed
 * by a, and return 'true' if and only if the allocation attempt succeeds.
 */
static bool
gmem_rb_match_one(struct gmem_rb_match_args *a, vm_offset_t beg,
    vm_offset_t end, vm_offset_t maxaddr)
{
	vm_offset_t bs, start;

	a->entry->start = roundup2(beg + GMEM_PAGE_SIZE,
	    a->uvas->format.alignment);
	if (a->entry->start + a->size > maxaddr)
		return (false);

	/* GMEM_PAGE_SIZE to create gap after new entry. */
	if (a->entry->start < beg + GMEM_PAGE_SIZE ||
	    a->entry->start + a->size + a->offset + GMEM_PAGE_SIZE > end)
		return (false);

	/* No boundary crossing. */
	if (gmem_test_boundary(a->entry->start + a->offset, a->size,
	    a->uvas->format.boundary))
		return (true);

	/*
	 * The start + offset to start + offset + size region crosses
	 * the boundary.  Check if there is enough space after the
	 * next boundary after the beg.
	 */
	bs = rounddown2(a->entry->start + a->offset + a->uvas->format.boundary,
	    a->uvas->format.boundary);
	start = roundup2(bs, a->uvas->format.alignment);
	/* GMEM_PAGE_SIZE to create gap after new entry. */
	if (start + a->offset + a->size + GMEM_PAGE_SIZE <= end &&
	    start + a->offset + a->size <= maxaddr &&
	    gmem_test_boundary(start + a->offset, a->size,
	    a->uvas->format.boundary)) {
		a->entry->start = start;
		return (true);
	}

	/*
	 * Not enough space to align at the requested boundary, or
	 * boundary is smaller than the size, but allowed to split.
	 * We already checked that start + size does not overlap maxaddr.
	 *
	 * XXXKIB. It is possible that bs is exactly at the start of
	 * the next entry, then we do not have gap.  Ignore for now.
	 */
	if ((a->gas_flags & GMEM_MF_CANSPLIT) != 0) {
		a->size = bs - a->entry->start;
		return (true);
	}

	return (false);
}

static void
gmem_rb_match_insert(struct gmem_rb_match_args *a)
{
	bool found;

	/*
	 * The prev->end is always aligned on the page size, which
	 * causes page alignment for the entry->start too.  The size
	 * is checked to be multiple of the page size.
	 *
	 * The page sized gap is created between consequent
	 * allocations to ensure that out-of-bounds accesses fault.
	 */
	a->entry->end = a->entry->start + a->size;

	found = gmem_rb_insert(a->uvas, a->entry);
	KASSERT(found, ("found dup %p start %jx size %jx",
	    a->uvas, (uintmax_t)a->entry->start, (uintmax_t)a->size));
	a->entry->flags = GMEM_UVAS_ENTRY_MAP;
}

static int
gmem_rb_lowermatch(struct gmem_rb_match_args *a, struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_entry *child;
	vm_offset_t maxaddr = a->uvas->format.maxaddr;

	child = RB_RIGHT(entry, rb_entry);
	if (child != NULL && entry->end < maxaddr &&
	    gmem_rb_match_one(a, entry->end, child->first,
	    maxaddr)) {
		gmem_rb_match_insert(a);
		return (0);
	}
	if (entry->free_down < a->size + a->offset + GMEM_PAGE_SIZE)
		return (ENOMEM);
	if (entry->first >= maxaddr)
		return (ENOMEM);
	child = RB_LEFT(entry, rb_entry);
	if (child != NULL && 0 == gmem_rb_lowermatch(a, child))
		return (0);
	if (child != NULL && child->last < maxaddr &&
	    gmem_rb_match_one(a, child->last, entry->start,
	    maxaddr)) {
		gmem_rb_match_insert(a);
		return (0);
	}
	child = RB_RIGHT(entry, rb_entry);
	if (child != NULL && 0 == gmem_rb_lowermatch(a, child))
		return (0);
	return (ENOMEM);
}

static int
gmem_rb_lowermatch2(struct gmem_rb_match_args *a, struct gmem_uvas_entry *entry, int *call)
{
	struct gmem_uvas_entry *child;
	vm_offset_t maxaddr = a->uvas->format.maxaddr;

	*call = *call + 1;
	child = RB_RIGHT(entry, rb_entry);
	if (child != NULL && entry->end < maxaddr &&
	    gmem_rb_match_one(a, entry->end, child->first,
	    maxaddr)) {
		gmem_rb_match_insert(a);
		return (0);
	}
	if (entry->free_down < a->size + a->offset + GMEM_PAGE_SIZE)
		return (ENOMEM);
	if (entry->first >= maxaddr)
		return (ENOMEM);
	child = RB_LEFT(entry, rb_entry);
	if (child != NULL && 0 == gmem_rb_lowermatch2(a, child, call))
		return (0);
	if (child != NULL && child->last < maxaddr &&
	    gmem_rb_match_one(a, child->last, entry->start,
	    maxaddr)) {
		gmem_rb_match_insert(a);
		return (0);
	}
	child = RB_RIGHT(entry, rb_entry);
	if (child != NULL && 0 == gmem_rb_lowermatch2(a, child, call))
		return (0);
	if (*call == 0) panic("fuck?");
	return (ENOMEM);
}

// static int
// gmem_uvas_uppermatch(struct gmem_rb_match_args *a, struct gmem_uvas_entry *entry)
// {
// 	struct gmem_uvas_entry *child;

// 	if (entry->free_down < a->size + a->offset + GMEM_PAGE_SIZE)
// 		return (ENOMEM);
// 	if (entry->last < a->common->highaddr)
// 		return (ENOMEM);
// 	child = RB_LEFT(entry, rb_entry);
// 	if (child != NULL && 0 == gmem_uvas_uppermatch(a, child))
// 		return (0);
// 	if (child != NULL && child->last >= a->common->highaddr &&
// 	    gmem_rb_match_one(a, child->last, entry->start,
// 	    a->uvas->end)) {
// 		gmem_rb_match_insert(a);
// 		return (0);
// 	}
// 	child = RB_RIGHT(entry, rb_entry);
// 	if (child != NULL && entry->end >= a->common->highaddr &&
// 	    gmem_rb_match_one(a, entry->end, child->first,
// 	    a->uvas->end)) {
// 		gmem_rb_match_insert(a);
// 		return (0);
// 	}
// 	if (child != NULL && 0 == gmem_uvas_uppermatch(a, child))
// 		return (0);
// 	return (ENOMEM);
// }

static int
gmem_rb_find_space(struct gmem_uvas *uvas,
    // const struct bus_dma_tag_common *common, 
    vm_offset_t size,
    int offset, u_int flags, struct gmem_uvas_entry *entry)
{
	struct gmem_rb_match_args a;
	int error = GMEM_OK;
	int call = 0;

	GMEM_UVAS_LOCK(uvas);
	KASSERT(entry->flags == 0, ("dirty entry %p %p", uvas, entry));
	KASSERT((size & GMEM_PAGE_MASK) == 0, ("size %jx", (uintmax_t)size));

	a.uvas = uvas;
	a.size = size;
	a.offset = offset;
	// a.common = common;
	a.gas_flags = flags;
	a.entry = entry;

	/* Handle lower region. */
	START_STATS;
	// if (uvas->format.maxaddr > 0) {
		error = gmem_rb_lowermatch2(&a, RB_ROOT(&uvas->rb_root), &call);
		printf("lowermatch %d\n", call);
		// if (error == 0)
		// 	return (0);
		KASSERT(error == ENOMEM,
		    ("error %d from gmem_rb_lowermatch", error));
	// }
	FINISH_STATS(RB_LM, size >> 12);

	/* Handle upper region. */
	// if (common->highaddr >= uvas->end)
	// 	return (ENOMEM);
	// error = gmem_uvas_uppermatch(&a, RB_ROOT(&uvas->rb_root));
	KASSERT(error == ENOMEM,
	    ("error %d from gmem_uvas_uppermatch", error));
	// if (error != 0)
	// 	printf("gmem rb-allocator failed to find a space to insert, start : %lx, end : %lx, size: %lx\n",
	// 		entry->start, entry->end, size);
	GMEM_UVAS_UNLOCK(uvas);
	return (error);
}

static int
gmem_rb_alloc_region(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry,
    u_int flags)
{
	struct gmem_uvas_entry *next, *prev;
	bool found;

	GMEM_UVAS_ASSERT_LOCKED(uvas);

	if ((entry->start & GMEM_PAGE_MASK) != 0 ||
	    (entry->end & GMEM_PAGE_MASK) != 0)
		return (EINVAL);
	if (entry->start >= entry->end)
		return (EINVAL);
	if (entry->end >= uvas->format.maxaddr)
		return (EINVAL);

	next = RB_NFIND(gmem_uvas_entries_tree, &uvas->rb_root, entry);
	KASSERT(next != NULL, ("next must be non-null %p %jx", uvas,
	    (uintmax_t)entry->start));
	prev = RB_PREV(gmem_uvas_entries_tree, &uvas->rb_root, next);
	/* prev could be NULL */

	/*
	 * Adapt to broken BIOSes which specify overlapping RMRR
	 * entries.
	 *
	 * XXXKIB: this does not handle a case when prev or next
	 * entries are completely covered by the current one, which
	 * extends both ways.
	 */
	if (prev != NULL && prev->end > entry->start &&
	    (prev->flags & GMEM_UVAS_ENTRY_PLACE) == 0) {
		if ((flags & GMEM_MF_RMRR) == 0 ||
		    (prev->flags & GMEM_MF_RMRR) == 0)
			return (EBUSY);
		entry->start = prev->end;
	}
	if (next->start < entry->end &&
	    (next->flags & GMEM_UVAS_ENTRY_PLACE) == 0) {
		if ((flags & GMEM_MF_RMRR) == 0 ||
		    (next->flags & GMEM_MF_RMRR) == 0)
			return (EBUSY);
		entry->end = next->start;
	}
	if (entry->end == entry->start)
		return (0);

	if (prev != NULL && prev->end > entry->start) {
		/* This assumes that prev is the placeholder entry. */
		gmem_rb_remove(uvas, prev);
		prev = NULL;
	}
	if (next->start < entry->end) {
		gmem_rb_remove(uvas, next);
		next = NULL;
	}

	found = gmem_rb_insert(uvas, entry);
	KASSERT(found, ("found RMRR dup %p start %jx end %jx",
	    uvas, (uintmax_t)entry->start, (uintmax_t)entry->end));
	if ((flags & GMEM_MF_RMRR) != 0)
		entry->flags = GMEM_MF_RMRR;

// #ifdef INVARIANTS
// 	struct gmem_uvas_entry *ip, *in;
// 	ip = RB_PREV(gmem_uvas_entries_tree, &uvas->rb_root, entry);
// 	in = RB_NEXT(gmem_uvas_entries_tree, &uvas->rb_root, entry);
// 	KASSERT(prev == NULL || ip == prev,
// 	    ("RMRR %p (%jx %jx) prev %p (%jx %jx) ins prev %p (%jx %jx)",
// 	    entry, entry->start, entry->end, prev,
// 	    prev == NULL ? 0 : prev->start, prev == NULL ? 0 : prev->end,
// 	    ip, ip == NULL ? 0 : ip->start, ip == NULL ? 0 : ip->end));
// 	KASSERT(next == NULL || in == next,
// 	    ("RMRR %p (%jx %jx) next %p (%jx %jx) ins next %p (%jx %jx)",
// 	    entry, entry->start, entry->end, next,
// 	    next == NULL ? 0 : next->start, next == NULL ? 0 : next->end,
// 	    in, in == NULL ? 0 : in->start, in == NULL ? 0 : in->end));
// #endif

	return (0);
}

static void
gmem_rb_free_space(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{
	KASSERT((entry->flags & (GMEM_UVAS_ENTRY_PLACE | GMEM_UVAS_ENTRY_RMRR |
	    GMEM_UVAS_ENTRY_MAP)) == GMEM_UVAS_ENTRY_MAP,
	    ("permanent entry %p %p", uvas, entry));

	gmem_rb_remove(uvas, entry);
	entry->flags &= ~GMEM_UVAS_ENTRY_MAP;
// #ifdef INVARIANTS
// 	if (iommu_check_free)
// 		gmem_uvas_check_free(uvas);
// #endif
}

static void
gmem_rb_free_region(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_entry *next, *prev;

	GMEM_UVAS_ASSERT_LOCKED(uvas);
	KASSERT((entry->flags & (GMEM_UVAS_ENTRY_PLACE | GMEM_UVAS_ENTRY_RMRR |
	    GMEM_UVAS_ENTRY_MAP)) == GMEM_UVAS_ENTRY_RMRR,
	    ("non-RMRR entry %p %p", uvas, entry));

	prev = RB_PREV(gmem_uvas_entries_tree, &uvas->rb_root, entry);
	next = RB_NEXT(gmem_uvas_entries_tree, &uvas->rb_root, entry);
	gmem_rb_remove(uvas, entry);
	entry->flags &= ~GMEM_UVAS_ENTRY_RMRR;

	if (prev == NULL)
		gmem_rb_insert(uvas, uvas->first_place);
	if (next == NULL)
		gmem_rb_insert(uvas, uvas->last_place);
}

// remove all rb entries covered by the given span
static void
gmem_rb_free_span(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_entry *tmp, *prev;
	tmp = RB_NFIND(gmem_uvas_entries_tree, &uvas->rb_root, entry);
	do
	{
		prev = RB_PREV(gmem_uvas_entries_tree, &uvas->rb_root, tmp);
		if (prev->end <= entry->start || prev == tmp)
			break;
		if (entry->start <= prev->start && prev->end <= entry->end) {
			gmem_rb_remove(uvas, prev);
			gmem_uvas_free_entry(uvas, prev);
		}
	} while (1);

	if (entry->start <= tmp->start && tmp->end <= entry->end)
	{
		gmem_rb_remove(uvas, tmp);
		gmem_uvas_free_entry(uvas, tmp);
	}
}


static int
gmem_rb_reserve_region(struct gmem_uvas *uvas,
    vm_offset_t start, vm_offset_t end, struct gmem_uvas_entry *entry)
{
	int error;


	entry->start = start;
	entry->end = end;
	GMEM_UVAS_LOCK(uvas);
	error = gmem_rb_alloc_region(uvas, entry, GMEM_MF_RMRR);
	GMEM_UVAS_UNLOCK(uvas);
	if (error == 0)
		entry->flags |= GMEM_UVAS_ENTRY_UNMAPPED;
	return (error);
}

/*
 * As in iommu_gas_reserve_region, reserve [start, end), but allow for existing
 * entries.
 */
// TBH, I don't think we need this function. Directly use alloc_span_fixed should be good.
// int
// iommu_gas_reserve_region_extend(struct iommu_domain *domain,
//     iommu_gaddr_t start, iommu_gaddr_t end)
// {
// 	struct iommu_map_entry *entry, *next, *prev, key = {};
// 	iommu_gaddr_t entry_start, entry_end;
// 	int error;

// 	error = 0;
// 	entry = NULL;
// 	end = ummin(end, domain->end);
// 	while (start < end) {
// 		/* Preallocate an entry. */
// 		if (entry == NULL)
// 			entry = iommu_gas_alloc_entry(domain,
// 			    IOMMU_PGF_WAITOK);
// 		/* Calculate the free region from here to the next entry. */
// 		key.start = key.end = start;
// 		IOMMU_DOMAIN_LOCK(domain);
// 		next = RB_NFIND(iommu_gas_entries_tree, &domain->rb_root, &key);
// 		KASSERT(next != NULL, ("domain %p with end %#jx has no entry "
// 		    "after %#jx", domain, (uintmax_t)domain->end,
// 		    (uintmax_t)start));
// 		entry_end = ummin(end, next->start);
// 		prev = RB_PREV(iommu_gas_entries_tree, &domain->rb_root, next);
// 		if (prev != NULL)
// 			entry_start = ummax(start, prev->end);
// 		else
// 			entry_start = start;
// 		start = next->end;
// 		/* Reserve the region if non-empty. */
// 		if (entry_start != entry_end) {
// 			error = iommu_gas_reserve_region_locked(domain,
// 			    entry_start, entry_end, entry);
// 			if (error != 0)
// 				break;
// 			entry = NULL;
// 		}
// 		IOMMU_DOMAIN_UNLOCK(domain);
// 	}
// 	/* Release a preallocated entry if it was not used. */
// 	if (entry != NULL)
// 		iommu_gas_free_entry(domain, entry);
// 	return (error);
// }

#endif