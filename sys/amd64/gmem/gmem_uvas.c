/*-
 * 
 * This software was developed by Weixi Zhu <wxzhu@rice.edu>
 * for gmem project.
 *
 * GMEM is a generic memory management interface for CPU and devices
 * It currently only supports x86_64 platforms.
 *
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/domainset.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/selinfo.h>
#include <sys/smp.h>
#include <sys/pipe.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/vmem.h>
#include <sys/vmmeter.h>
#include <sys/tree.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

#include <sys/gmem.h>
#include <amd64/gmem/gmem_dev.h>
#include <amd64/gmem/gmem_uvas.h>

static gmem_error_t gmem_uvas_alloc_span(gmem_uvas_t *uvas, vm_offset_t *start, 
	vm_size_t size, vm_prot_t protection, dev_pmap_t *pmap, 
	gmem_uvas_entry_t *entry);
// gmem_error_t gmem_uvas_free_span(gmem_uvas_t *uvas, vm_offset_t start,
// 	vm_size_t size);

static uma_zone_t gmem_uvas_entry_zone;

static void
gmem_uvas_zone_init(void)
{

	gmem_uvas_entry_zone = uma_zcreate("GMEM_UVAS_ENTRY",
	    sizeof(struct gmem_uvas_entry), NULL, NULL,
	    NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NODUMP);
}
SYSINIT(gmem_uvas, SI_SUB_DRIVERS, SI_ORDER_FIRST, gmem_uvas_zone_init, NULL);

static struct gmem_uvas_entry *
gmem_uvas_alloc_entry(struct gmem_uvas *uvas, u_int flags)
{
	struct gmem_uvas_entry *res;

	KASSERT((flags & ~(GMEM_WAITOK)) == 0,
	    ("unsupported flags %x", flags));

	res = uma_zalloc(gmem_uvas_entry_zone, ((flags & GMEM_WAITOK) !=
	    0 ? M_WAITOK : M_NOWAIT) | M_ZERO);
	if (res != NULL) {
		res->uvas = uvas;
		atomic_add_int(&uvas->entries_cnt, 1);
	}
	return (res);
}

static void
gmem_uvas_free_entry(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{

	KASSERT(uvas == entry->uvas,
	    ("mismatched free uvas %p entry %p entry->uvas %p", uvas,
	    entry, entry->uvas));
	atomic_subtract_int(&uvas->entries_cnt, 1);
	uma_zfree(gmem_uvas_entry_zone, entry);
}

static int gmem_uvas_cmp_entries(struct gmem_uvas_entry *a, struct gmem_uvas_entry *b)
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
gmem_uvas_augment_entry(struct gmem_uvas_entry *entry)
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
    gmem_uvas_cmp_entries);

static bool
gmem_uvas_rb_insert(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_entry *found;

	found = RB_INSERT(gmem_uvas_entries_tree,
	    &uvas->rb_root, entry);
	return (found == NULL);
}

static void
gmem_uvas_rb_remove(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{

	RB_REMOVE(gmem_uvas_entries_tree, &uvas->rb_root, entry);
}

static void
gmem_uvas_init_rbtree(struct gmem_uvas *uvas)
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
	iommu_gas_rb_insert(uvas, begin);

	end->start = uvas->end;
	end->end = uvas->end;
	end->flags = GMEM_UVAS_ENTRY_PLACE | GMEM_UVAS_ENTRY_UNMAPPED;
	iommu_gas_rb_insert(uvas, end);

	uvas->first_place = begin;
	uvas->last_place = end;
	// uvas->flags |= IOMMU_DOMAIN_GAS_INITED;
	GMEM_UVAS_UNLOCK(uvas);
}

static void
gmem_uvas_fini_uvas(struct gmem_uvas *uvas)
{
	struct gmem_uvas_entry *entry, *entry1;

	GMEM_UVAS_ASSERT_LOCKED(uvas);
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
struct gmem_uvas_match_args {
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
gmem_uvas_match_one(struct gmem_uvas_match_args *a, vm_offset_t beg,
    vm_offset_t end, vm_offset_t maxaddr)
{
	vm_offset_t bs, start;

	a->entry->start = roundup2(beg + GMEM_PAGE_SIZE,
	    a->uvas->format->alignment);
	if (a->entry->start + a->size > maxaddr)
		return (false);

	/* GMEM_PAGE_SIZE to create gap after new entry. */
	if (a->entry->start < beg + GMEM_PAGE_SIZE ||
	    a->entry->start + a->size + a->offset + GMEM_PAGE_SIZE > end)
		return (false);

	/* No boundary crossing. */
	if (gmem_test_boundary(a->entry->start + a->offset, a->size,
	    a->uvas->format->boundary))
		return (true);

	/*
	 * The start + offset to start + offset + size region crosses
	 * the boundary.  Check if there is enough space after the
	 * next boundary after the beg.
	 */
	bs = rounddown2(a->entry->start + a->offset + a->uvas->format->boundary,
	    a->uvas->format->boundary);
	start = roundup2(bs, a->uvas->format->alignment);
	/* GMEM_PAGE_SIZE to create gap after new entry. */
	if (start + a->offset + a->size + GMEM_PAGE_SIZE <= end &&
	    start + a->offset + a->size <= maxaddr &&
	    gmem_test_boundary(start + a->offset, a->size,
	    a->uvas->format->boundary)) {
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
gmem_uvas_match_insert(struct gmem_uvas_match_args *a)
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

	found = gmem_uvas_rb_insert(a->uvas, a->entry);
	KASSERT(found, ("found dup %p start %jx size %jx",
	    a->uvas, (uintmax_t)a->entry->start, (uintmax_t)a->size));
	a->entry->flags = GMEM_UVAS_ENTRY_MAP;
}

static int
gmem_uvas_lowermatch(struct gmem_uvas_match_args *a, struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_entry *child;
	vm_offset_t maxaddr = a->uvas->format->maxaddr;

	child = RB_RIGHT(entry, rb_entry);
	if (child != NULL && entry->end < maxaddr &&
	    gmem_uvas_match_one(a, entry->end, child->first,
	    maxaddr)) {
		gmem_uvas_match_insert(a);
		return (0);
	}
	if (entry->free_down < a->size + a->offset + GMEM_PAGE_SIZE)
		return (ENOMEM);
	if (entry->first >= maxaddr)
		return (ENOMEM);
	child = RB_LEFT(entry, rb_entry);
	if (child != NULL && 0 == gmem_uvas_lowermatch(a, child))
		return (0);
	if (child != NULL && child->last < maxaddr &&
	    gmem_uvas_match_one(a, child->last, entry->start,
	    maxaddr)) {
		gmem_uvas_match_insert(a);
		return (0);
	}
	child = RB_RIGHT(entry, rb_entry);
	if (child != NULL && 0 == gmem_uvas_lowermatch(a, child))
		return (0);
	return (ENOMEM);
}

// static int
// gmem_uvas_uppermatch(struct gmem_uvas_match_args *a, struct gmem_uvas_entry *entry)
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
// 	    gmem_uvas_match_one(a, child->last, entry->start,
// 	    a->uvas->end)) {
// 		gmem_uvas_match_insert(a);
// 		return (0);
// 	}
// 	child = RB_RIGHT(entry, rb_entry);
// 	if (child != NULL && entry->end >= a->common->highaddr &&
// 	    gmem_uvas_match_one(a, entry->end, child->first,
// 	    a->uvas->end)) {
// 		gmem_uvas_match_insert(a);
// 		return (0);
// 	}
// 	if (child != NULL && 0 == gmem_uvas_uppermatch(a, child))
// 		return (0);
// 	return (ENOMEM);
// }

static int
gmem_uvas_find_space(struct gmem_uvas *uvas,
    // const struct bus_dma_tag_common *common, 
    vm_offset_t size,
    int offset, u_int flags, struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_match_args a;
	int error;

	GMME_UVAS_ASSERT_LOCKED(uvas);
	KASSERT(entry->flags == 0, ("dirty entry %p %p", uvas, entry));
	KASSERT((size & GMEM_PAGE_MASK) == 0, ("size %jx", (uintmax_t)size));

	a.uvas = uvas;
	a.size = size;
	a.offset = offset;
	// a.common = common;
	a.gas_flags = flags;
	a.entry = entry;

	/* Handle lower region. */
	if (uvas->format->maxaddr > 0) {
		error = gmem_uvas_lowermatch(&a, RB_ROOT(&uvas->rb_root));
		if (error == 0)
			return (0);
		KASSERT(error == ENOMEM,
		    ("error %d from gmem_uvas_lowermatch", error));
	}
	/* Handle upper region. */
	// if (common->highaddr >= uvas->end)
	// 	return (ENOMEM);
	// error = gmem_uvas_uppermatch(&a, RB_ROOT(&uvas->rb_root));
	KASSERT(error == ENOMEM,
	    ("error %d from gmem_uvas_uppermatch", error));
	return (error);
}

static int
gmem_uvas_alloc_region(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry,
    u_int flags)
{
	struct gmem_uvas_entry *next, *prev;
	bool found;

	GMME_UVAS_ASSERT_LOCKED(uvas);

	if ((entry->start & GMEM_PAGE_MASK) != 0 ||
	    (entry->end & GMEM_PAGE_MASK) != 0)
		return (EINVAL);
	if (entry->start >= entry->end)
		return (EINVAL);
	if (entry->end >= uvas->end)
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
		    (prev->flags & GMEM_UVAS_ENTRY_RMRR) == 0)
			return (EBUSY);
		entry->start = prev->end;
	}
	if (next->start < entry->end &&
	    (next->flags & GMEM_UVAS_ENTRY_PLACE) == 0) {
		if ((flags & GMEM_MF_RMRR) == 0 ||
		    (next->flags & GMEM_UVAS_ENTRY_RMRR) == 0)
			return (EBUSY);
		entry->end = next->start;
	}
	if (entry->end == entry->start)
		return (0);

	if (prev != NULL && prev->end > entry->start) {
		/* This assumes that prev is the placeholder entry. */
		gmem_uvas_rb_remove(uvas, prev);
		prev = NULL;
	}
	if (next->start < entry->end) {
		gmem_uvas_rb_remove(uvas, next);
		next = NULL;
	}

	found = gmem_uvas_rb_insert(uvas, entry);
	KASSERT(found, ("found RMRR dup %p start %jx end %jx",
	    uvas, (uintmax_t)entry->start, (uintmax_t)entry->end));
	if ((flags & GMEM_MF_RMRR) != 0)
		entry->flags = GMEM_UVAS_ENTRY_RMRR;

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

void
gmem_uvas_free_space(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{

	GMME_UVAS_ASSERT_LOCKED(uvas);
	KASSERT((entry->flags & (GMEM_UVAS_ENTRY_PLACE | GMEM_UVAS_ENTRY_RMRR |
	    GMEM_UVAS_ENTRY_MAP)) == GMEM_UVAS_ENTRY_MAP,
	    ("permanent entry %p %p", uvas, entry));

	gmem_uvas_rb_remove(uvas, entry);
	entry->flags &= ~GMEM_UVAS_ENTRY_MAP;
// #ifdef INVARIANTS
// 	if (iommu_check_free)
// 		gmem_uvas_check_free(uvas);
// #endif
}

void
gmem_uvas_free_region(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_entry *next, *prev;

	GMME_UVAS_ASSERT_LOCKED(uvas);
	KASSERT((entry->flags & (GMEM_UVAS_ENTRY_PLACE | GMEM_UVAS_ENTRY_RMRR |
	    GMEM_UVAS_ENTRY_MAP)) == GMEM_UVAS_ENTRY_RMRR,
	    ("non-RMRR entry %p %p", uvas, entry));

	prev = RB_PREV(gmem_uvas_entries_tree, &uvas->rb_root, entry);
	next = RB_NEXT(gmem_uvas_entries_tree, &uvas->rb_root, entry);
	gmem_uvas_rb_remove(uvas, entry);
	entry->flags &= ~GMEM_UVAS_ENTRY_RMRR;

	if (prev == NULL)
		gmem_uvas_rb_insert(uvas, uvas->first_place);
	if (next == NULL)
		gmem_uvas_rb_insert(uvas, uvas->last_place);
}

// remove all rb entries covered by the given span
static void
gmem_uvas_rb_free_span(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{
	struct gmem_uvas_entry *tmp, *prev;
	tmp = RB_NFIND(gmem_uvas_entries_tree, &uvas->rb_root, entry);
	do
	{
		prev = RB_PREV(gmem_uvas_entries_tree, &uvas->rb_root, tmp);
		if (prev->end <= entry->start || prev == tmp)
			break;
		if (entry->start <= prev->start && prev->end <= entry->end) {
			gmem_uvas_rb_remove(uvas, prev);
			gmem_uvas_free_entry(uvas, prev);
		}
	} while (1);

	if (entry->start <= tmp->start && tmp->end <= entry->end)
	{
		gmem_uvas_rb_remove(uvas, tmp);
		gmem_uvas_free_entry(uvas, tmp);
	}
}

// Three modes to use uvas:
// 	1. private: pmap is NULL && replicate == false
//  2. shared: uvas and pmap are both not NULL, replicate == false
//  3. replicate: uvas and pmap are both not NULL, replicate == true
//     TODO: change this mode to share CPU vma, consider the opencl case.
//  lookup: faultable device requires looking up uvas entries 
gmem_error_t gmem_uvas_create(gmem_uvas_t **uvas_res, gmem_dev_t *dev,
	dev_pmap_t *pmap, void *dev_data, bool replicate, bool need_lookup,
	vm_offset_t alignment, vm_offset_t boundary, vm_offset_t size)
{
	gmem_uvas_t uvas;
	if (*uvas_res == NULL)
	{
		KASSERT(*pmap == NULL, "Creating a uvas with non-null pmap");
		KASSERT(dev_data == NULL, "Creating a uvas with non-null dev-specific data");

		// allocate and create the pmap with dev->mmu_ops
		pmap = malloc(sizeof(dev_pmap_t), M_DEVBUF, M_WAITOK | M_ZERO);
		// allocate and create the uvas
		uvas = malloc(sizeof(gmem_uvas_t), M_DEVBUF, M_WAITOK | M_ZERO);

		// initialize pmap
		pmap->ndevices = 1;
		TAILQ_INIT(pmap->gmem_dev_header);
		TAILQ_INSERT_TAIL(&pmap->gmem_dev_header, dev, gmem_dev_list);
		pmap->mmu_ops = dev->mmu_ops;
		pmap->pmap_replica = NULL;
		pmap->uvas = uvas;

		// use mmu callback to initialize device-specific data
		pmap->mmu_ops->mmu_pmap_create(&pmap->data, dev_data);

		// initialize uvas
		TAILQ_INIT(uvas->uvas_entry_header);
		TAILQ_INIT(uvas->dev_pmap_header);

		// insert pmap to uvas pmap list
		TAILQ_INSERT_TAIL(&uvas->dev_pmap_header, pmap, unified_pmap_list);

		// insert pmap to dev pmap list
		// I don't think that this is necessary.
		// TODO: consider delete pmap field in gmem_dev

		uvas->format.alignment = alignment;
		uvas->format.boundary = boundary;
		uvas->format.maxaddr = size;

		if (need_lookup)
		{
			uvas->allocator = RBTREE;
			// TODO: RB-TREE
			gmem_uvas_init_rbtree(uvas);
		}
		else
		{
			uvas->allocator = VMEM;
			// Currently we use no quantum cache
			uvas->arena = vmem_create("uva", 0, 
				rounddown(dev->vma_format->maxaddr, dev->vma_format->alignment),
				dev->vma_format->alignment, 0, M_WAITOK);
		}
	}
	else
	{
		// attach dev and pmap to the uvas
		panic("Attaching to a uvas is not implemented");
	}
	*uvas_res = uvas;
	return GMEM_OK;
}

gmem_error_t gmem_uvas_delete(gmem_uvas_t *uvas)
{
	KASSERT(uvas != NULL, "The uvas to be deleted is NULL!");

	// traverse all pmaps of the uvas and delete them

	// free the uvas
	return GMEM_OK;
}

gmem_error_t gmem_uvas_alloc_and_insert_span(gmem_uvas_t *uvas, 
	vm_offset_t *start, vm_size_t size, vm_prot_t protection, u_int flags)
{
	gmem_uvas_entry *entry;
	int error;

	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
	entry = gmem_uvas_alloc_entry(uvas, (flags & GMEM_MF_CANWAIT) != 0 ? GMEM_WAITOK:0);
	if (entry == NULL)
		return (GMEM_ENOMEM);

	GMEM_UVAS_LOCK(uvas);
	if (uvas->uvas_allocator == RBTREE)
	{
		// use rb-tree allocator
		error = gmem_uvas_find_space(uvas, size, offset, flags, entry);
		if (error == GMEM_ENOMEM) {
			GMEM_UVAS_UNLOCK(uvas);
			gmem_uvas_free_entry(uvas, entry);
			return (error);
		}
		// [TODO]
		// entry->flags |= eflags;
		*start = entry->start;
	}
	else if (uvas->uvas_allocator == VMEM)
	{
		// use vmem allocator
		printf("VMEM Allocator not implemented!\n");
	}
	GMEM_UVAS_UNLOCK(uvas);
	return GMEM_OK;
}

gmem_error_t gmem_uvas_free_span(gmem_uvas_t *uvas, vm_offset_t start,
	vm_size_t size)
{
	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
	GMEM_UVAS_LOCK(uvas);
	if (uvas->uvas_allocator == RBTREE)
	{
		// use rb-tree allocator
		struct gmem_uvas_entry entry;
			// = gmem_uvas_alloc_entry(uvas, 0);
		if (entry == NULL)
			return (GMEM_ENOMEM);
		entry.start = start;
		entry.end = start + size;
		gmem_uvas_rb_free_span(uvas, &entry);
	}
	else if (uvas->uvas_allocator == VMEM)
	{
		// use vmem allocator
	}
	GMEM_UVAS_UNLOCK(uvas);
	return GMEM_OK;
}

gmem_error_t gmem_uvas_map_pages(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, vm_page_t first_page)
{
	KASSERT(pmap != NULL, "The pmap to map is NULL!");

	return GMEM_OK;
}

gmem_error_t gmem_uvas_map_pages_sg(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, vm_page_t *pages)
{
	KASSERT(pmap != NULL, "The pmap to map is NULL!");


	return GMEM_OK;
}

gmem_error_t gmem_uvas_unmap(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, void (* unmap_callback(void *)), void *callback_args)
{
	KASSERT(pmap != NULL, "The pmap to unmap is NULL!");

	// Think about how to async?
	if (unmap_callback == NULL)
	{
		// The unmap will be sync
	}
	else
	{
		// The unmap will be async
	}

	return GMEM_OK;
}

gmem_error_t gmem_uvas_protect(gmem_uvas_t *uvas, vm_offset_t start,
	vm_size_t size, vm_prot_t new_protection)
{
	KASSERT(uvas != NULL, "The uvas to mutate protection is NULL!");

	return GMEM_OK;
}