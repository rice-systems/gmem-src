/*-
 * 
 * This software was developed by Weixi Zhu <wxzhu@rice.edu>
 * for gmem project.
 *
 * GMEM is a generic memory management interface for CPU and devices
 * It currently only supports x86_64 platforms.
 *
 */

#define	RB_AUGMENT(entry) gmem_rb_augment_entry(entry)
#include <sys/tree.h>

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
#include <sys/sched.h>
#include <sys/kthread.h>
#include <sys/unistd.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

#include <vm/gmem.h>
#include <vm/gmem_dev.h>
#include <vm/gmem_uvas.h>
#include <vm/gmem_rb_tree.h>

static uma_zone_t gmem_uvas_entry_zone;
static uma_zone_t gmem_uvas_unmap_requests_zone;
static void gmem_uvas_generic_unmap_handler(gmem_uvas_t *uvas);
static void gmem_uvas_async_unmap_start(gmem_uvas_t *uvas);

static void
gmem_uvas_zone_init(void)
{
	gmem_uvas_entry_zone = uma_zcreate("GMEM_UVAS_ENTRY",
	    sizeof(struct gmem_uvas_entry), NULL, NULL,
	    NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NODUMP);
	gmem_uvas_unmap_requests_zone = uma_zcreate("GMEM_UVAS_UNMAP_REQUEST",
	    sizeof(struct unmap_request), NULL, NULL,
	    NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NODUMP);
}
SYSINIT(gmem_uvas, SI_SUB_DRIVERS, SI_ORDER_FIRST, gmem_uvas_zone_init, NULL);

struct gmem_uvas_entry *
gmem_uvas_alloc_entry(struct gmem_uvas *uvas, u_int flags)
{
	struct gmem_uvas_entry *res;

	KASSERT((flags & ~(GMEM_WAITOK)) == 0,
	    ("unsupported flags %x", flags));

	res = uma_zalloc(gmem_uvas_entry_zone, ((flags & GMEM_WAITOK) !=
	    0 ? M_WAITOK : M_NOWAIT) | M_ZERO);
	if (res != NULL) {
		res->uvas = uvas;
		if (instrument)
			atomic_add_int(&uvas->entries_cnt, 1);
	}
	else
		printf("gmem_uvas_alloc_entry NOMEM\n");
	return (res);
}

void
gmem_uvas_free_entry(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry)
{

	KASSERT(uvas == entry->uvas,
	    ("mismatched free uvas %p entry %p entry->uvas %p", uvas,
	    entry, entry->uvas));
	if (instrument)
		atomic_subtract_int(&uvas->entries_cnt, 1);
	uma_zfree(gmem_uvas_entry_zone, entry);
}

static inline void create_unique_uvas(
	gmem_uvas_t **uvas_res, 
	dev_pmap_t **pmap_res, 
	gmem_mmu_ops_t *mmu_ops,
	dev_pmap_t *pmap_to_share, 
	void *dev_data, 
	vm_offset_t alignment, 
	vm_offset_t boundary, 
	vm_offset_t size,
	vm_offset_t guard)
{
	// allocate and create the pmap with dev->mmu_ops
	dev_pmap_t *pmap = (dev_pmap_t *) malloc(sizeof(dev_pmap_t), M_DEVBUF, M_WAITOK | M_ZERO);
	// allocate and create the uvas
	gmem_uvas_t *uvas = (gmem_uvas_t *) malloc(sizeof(gmem_uvas_t), M_DEVBUF, M_WAITOK | M_ZERO);
	mtx_init(&uvas->lock, "uvas", NULL, MTX_DEF);
	mtx_init(&uvas->enqueue_lock, "uvas unmap request enqueue", NULL, MTX_DEF);
	mtx_init(&uvas->dequeue_lock, "uvas unmap request dequeue", NULL, MTX_DEF);

	// useless gmem_dev structs?
	// pmap->ndevices = 1;
	// TAILQ_INIT(&pmap->gmem_dev_header);
	// TAILQ_INSERT_TAIL(&pmap->gmem_dev_header, dev, gmem_dev_list);

	pmap->pmap_replica = NULL;
	pmap->uvas = uvas;

	// use mmu callback to initialize device-specific data
	mmu_ops->mmu_init(mmu_ops);
	pmap->data = dev_data;
	pmap->mmu_ops = mmu_ops;
	pmap->mmu_ops->mmu_pmap_create(pmap);

	// initialize uvas
	TAILQ_INIT(&uvas->mapped_entries);
	TAILQ_INIT(&uvas->unmap_requests);
	TAILQ_INIT(&uvas->unmap_workspace);
	TAILQ_INIT(&uvas->dev_pmap_header);
	uvas->unmap_pages = 0;
	uvas->unmap_working_pages = 0;

	// Need a flag to enable uvas daemon?
	gmem_uvas_async_unmap_start(uvas);

	// insert pmap to uvas pmap list
	TAILQ_INSERT_TAIL(&uvas->dev_pmap_header, pmap, unified_pmap_list);

	// insert pmap to dev pmap list
	// I don't think that this is necessary.
	// TODO: consider delete pmap field in gmem_dev

	uvas->format.alignment = alignment;
	uvas->format.boundary = boundary;
	uvas->format.maxaddr = size;
	uvas->format.guard = guard;

	// Edge device does not need to perform page faults
	if (0) {
		uvas->allocator = RBTREE;
		// TODO: RB-TREE
		gmem_rb_init(uvas);
	} else {
		uvas->allocator = VMEM;
		// Currently we use the maximum available quantum cache (16)
		// nextfit/bestfit/firstfit do not impact iommu netperf performance.
		uvas->arena = vmem_create("uva", 0, rounddown(size, alignment), 
			alignment, alignment * 16, M_WAITOK | M_BESTFIT);
	}

	*uvas_res = uvas;
	*pmap_res = pmap;
}

static inline void create_cpu_share_uvas(
	gmem_uvas_t **uvas_res, 
	dev_pmap_t **pmap_res, 
	gmem_mmu_ops_t *mmu_ops,
	void *dev_data)
{
	// allocate and create the pmap with dev->mmu_ops
	dev_pmap_t *pmap = (dev_pmap_t *) malloc(sizeof(dev_pmap_t), M_DEVBUF, M_WAITOK | M_ZERO);
	// allocate and create the uvas
	gmem_uvas_t *uvas = (gmem_uvas_t *) malloc(sizeof(gmem_uvas_t), M_DEVBUF, M_WAITOK | M_ZERO);
	mtx_init(&uvas->lock, "uvas", NULL, MTX_DEF);
	mtx_init(&uvas->enqueue_lock, "uvas unmap request enqueue", NULL, MTX_DEF);
	mtx_init(&uvas->dequeue_lock, "uvas unmap request dequeue", NULL, MTX_DEF);

	// useless gmem_dev structs?
	// pmap->ndevices = 1;
	// TAILQ_INIT(&pmap->gmem_dev_header);
	// TAILQ_INSERT_TAIL(&pmap->gmem_dev_header, dev, gmem_dev_list);

	pmap->pmap_replica = NULL;
	pmap->uvas = uvas;

	// use mmu callback to initialize device-specific data
	mmu_ops->mmu_init(mmu_ops);
	pmap->data = dev_data;
	pmap->mmu_ops = mmu_ops;
	pmap->mmu_ops->mmu_pmap_create(pmap);

	// initialize uvas
	TAILQ_INIT(&uvas->mapped_entries);
	TAILQ_INIT(&uvas->unmap_requests);
	TAILQ_INIT(&uvas->unmap_workspace);
	TAILQ_INIT(&uvas->dev_pmap_header);
	uvas->unmap_pages = 0;
	uvas->unmap_working_pages = 0;

	// Need a flag to enable uvas daemon?
	gmem_uvas_async_unmap_start(uvas);

	// insert pmap to uvas pmap list
	TAILQ_INSERT_TAIL(&uvas->dev_pmap_header, pmap, unified_pmap_list);

	// pmap replicates CPU ptes
	uvas->allocator = CPU_VM;

	if (uvas_res != NULL)
		*uvas_res = uvas;
	if (pmap_res != NULL)
		*pmap_res = pmap;
}

// Four modes to use uvas:
// 	1. private: pmap is NULL && replicate == false
//  2. shared: uvas and pmap are both not NULL, replicate == false
//  3. replicate: uvas and pmap are both not NULL, replicate == true
//  4. unique: the device is an edge device and the uvas has a single pmap
//     TODO: change this mode to share CPU vma, consider the opencl case.
//  lookup: faultable device requires looking up uvas entries 
gmem_error_t gmem_uvas_create(
	gmem_uvas_t **uvas_res, 
	dev_pmap_t **pmap_res, 
	gmem_dev_t *dev, // this argument is never used, consider removing it.
	gmem_mmu_ops_t *mmu_ops,
	dev_pmap_t *pmap_to_share, 
	void *dev_data, 
	int mode,
	vm_offset_t alignment, 
	vm_offset_t boundary, 
	vm_offset_t size,
	vm_offset_t guard)
{
	switch (mode) {
		case GMEM_UVAS_UNIQUE:
			if (!(uvas_res != NULL && *uvas_res == NULL && 
				pmap_res != NULL && *pmap_res == NULL &&
				mmu_ops != NULL && pmap_to_share == NULL && dev_data != NULL))
				return GMEM_EINVALIDARGS;
			create_unique_uvas(uvas_res, pmap_res, mmu_ops, pmap_to_share,
				dev_data, alignment, boundary, size, guard);
			break;
		case GMEM_UVAS_SHARE_CPU:
			printf("[gmem] %s: trying to share CPU process address space\n", __func__);
			if (!(mmu_ops != NULL && dev_data != NULL))
				return GMEM_EINVALIDARGS;
			create_cpu_share_uvas(uvas_res, pmap_res, mmu_ops, dev_data);
			break;
		default:
			printf("Other UVAS creation modes are not implemented\n");
			return GMEM_EINVALIDARGS;

	}
	return GMEM_OK;
}

gmem_error_t pmap_reload_mmu(dev_pmap_t *pmap, gmem_mmu_ops_t *new_mmu)
{
	new_mmu->mmu_init(new_mmu);
	pmap->mmu_ops = new_mmu;
	return GMEM_OK;
}

gmem_error_t gmem_uvas_delete(gmem_uvas_t *uvas)
{
	KASSERT(uvas != NULL, ("The uvas to be deleted is NULL!"));

	GMEM_UVAS_LOCK(uvas);
	// traverse all pmaps of the uvas and delete them
	if (uvas != NULL) {
		// delete all mappings first
		// domain_free_pgtbl(domain);

		// delete all va allocations
		if (uvas->allocator == RBTREE) {
			gmem_rb_destroy(uvas);
		} else if (uvas->allocator == VMEM) {
			vmem_destroy(uvas->arena);
			uvas->arena = NULL;
		}
	}
	GMEM_UVAS_UNLOCK(uvas);
	// free the uvas
	// TODO: WE need to finish this, although the current code does not seem to touch it.
	return GMEM_OK;
}

// Allocate [start, size + uvas->format.guard], i.e. with holes
gmem_error_t gmem_uvas_alloc_span(gmem_uvas_t *uvas, 
	vm_offset_t *start, vm_size_t size, vm_prot_t protection, u_int flags, gmem_uvas_entry_t **ret)
{
	gmem_uvas_entry_t *entry;
	int error;

	KASSERT(uvas != NULL, ("The uvas to allocate entry is NULL!"));
	entry = gmem_uvas_alloc_entry(uvas, (flags & GMEM_MF_CANWAIT) != 0 ? GMEM_WAITOK:0);
	if (entry == NULL)
		return (GMEM_ENOMEM);

	START_STATS;
	if (uvas->allocator == RBTREE)
	{
		// use rb-tree allocator
		// TODO: offset makes no sense. (Offset is effectively a bug.)
		error = gmem_rb_find_space(uvas, size + uvas->format.guard, flags, entry);
		if (error == GMEM_ENOMEM) {
			gmem_uvas_free_entry(uvas, entry);
			return (error);
		}
		// [TODO]
		// entry->flags |= eflags;
		*start = entry->start;
	}
	else if (uvas->allocator == VMEM)
	{
		// use vmem allocator
		error = vmem_alloc(uvas->arena, size + uvas->format.guard, M_FIRSTFIT | ((flags & GMEM_MF_CANWAIT) != 0 ?
			M_WAITOK : M_NOWAIT), start);
		if (error != 0)
			return error;
		else {
			entry->start = *start;
			entry->end = *start + size + uvas->format.guard;
		}
	}
    FINISH_STATS(UVAS_INST_VA_ALLOC, size >> 12);

	if (ret != NULL)
		*ret = entry;
	return GMEM_OK;
}

gmem_error_t gmem_uvas_alloc_span_fixed(gmem_uvas_t *uvas, 
	vm_offset_t start, vm_offset_t end, vm_prot_t protection, u_int flags, gmem_uvas_entry_t **ret)
{
	gmem_uvas_entry_t *entry;
	int error;

	if (start >= end) {
		debug_printf("Trying to allocate an invalid va span, start %lx end %lx\n", start, end);
		return GMEM_EINVALIDARGS;
	}
	
	KASSERT(uvas != NULL, ("The uvas to allocate entry is NULL!"));
	entry = gmem_uvas_alloc_entry(uvas, (flags & GMEM_MF_CANWAIT) != 0 ? GMEM_WAITOK:0);
	if (entry == NULL)
		return (GMEM_ENOMEM);

	START_STATS;
	if (uvas->allocator == RBTREE)
	{
		// use rb-tree allocator
		error = gmem_rb_reserve_region(uvas, start, end + uvas->format.guard, entry);
		if (error != 0) {
			gmem_uvas_free_entry(uvas, entry);
			return (error);
		}
	}
	else if (uvas->allocator == VMEM)
	{
		vm_offset_t new_start;
		// use vmem allocator
		error = 0;
		error = vmem_xalloc(uvas->arena, end + uvas->format.guard - start, 0, 0, 0, start, end + uvas->format.guard, 
			M_FIRSTFIT | ((flags & GMEM_MF_CANWAIT) != 0 ? M_WAITOK : M_NOWAIT), &new_start);
		if (start != new_start) {
			debug_printf("VMEM xalloc failed with start %lx, end %lx, newstart %lx\n", start, end, new_start);
		}
		if (error != 0) {
			gmem_uvas_free_entry(uvas, entry);
			return error;
		}
		else {
			entry->start = start;
			entry->end = end + uvas->format.guard;
			entry->flags |= GMEM_UVAS_VMEM_XALLOC;
		}
	}
    FINISH_STATS(UVAS_INST_VA_ALLOC, (end - start) >> 12);

	if (ret != NULL)
		*ret = entry;
	return GMEM_OK;
}

gmem_error_t gmem_uvas_free_span(gmem_uvas_t *uvas, gmem_uvas_entry_t *entry)
{
	KASSERT(uvas != NULL, ("The uvas to allocate entry is NULL!"));
	if (uvas == NULL) {
		panic("[gmem panic] uvas is null\n");
		return -1;
	}

    START_STATS;
	if (uvas->allocator == RBTREE) {
		// use rb-tree allocator
		GMEM_UVAS_LOCK(uvas);
		// if (entry != NULL) {
			gmem_rb_remove(uvas, entry);
			gmem_uvas_free_entry(uvas, entry);
		// } else {
		// 	gmem_uvas_entry_t span;
		// 	span.start = start;
		// 	span.end = start + size;
		// 	// TODO: use gmem_rb_free_span as a general operation.
		// 	gmem_rb_free_span(uvas, &span);
		// }
		GMEM_UVAS_UNLOCK(uvas);
	}
	else if (uvas->allocator == VMEM) {
		if ((entry->flags & GMEM_UVAS_VMEM_XALLOC) == 0) {
			vmem_free(uvas->arena, entry->start, entry->end - entry->start);
		} else {
			vmem_xfree(uvas->arena, entry->start, entry->end - entry->start);
		}
		gmem_uvas_free_entry(uvas, entry);
	}
	FINISH_STATS(UVAS_INST_VA_FREE, (entry->end - entry->start - uvas->format.guard) >> 12);
	return GMEM_OK;
}

gmem_error_t gmem_uvas_map_pages(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, vm_page_t first_page, u_int prot, u_int mem_flags)
{
	KASSERT(pmap != NULL, ("The pmap to map is NULL!"));

	if (size & PAGE_MASK)
		return GMEM_EINVALIDARGS;
	pmap->mmu_ops->mmu_pmap_enter(pmap, start, size, VM_PAGE_TO_PHYS(first_page),
		prot, mem_flags);
	return GMEM_OK;
}

// Map a list of scattered 4KB pages
// This interface used to coalesce contiguous scattered pages.
// However, it is totally unnecessary. What is the probability for scattered pages to be contig?
static inline gmem_error_t gmem_uvas_prepare_and_map_pages_sg(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, vm_page_t *pages, u_int prot, u_int mem_flags, int coalesce)
{
	vm_offset_t i, last_i = 0;

	if (pmap == NULL || size < GMEM_PAGE_SIZE)
		return GMEM_EINVALIDARGS;

	if (coalesce) {
		// coalesce mapping requests
		while(last_i * GMEM_PAGE_SIZE < size) {
			i = last_i;

			// advance when contiguous
			while((i + 1) * GMEM_PAGE_SIZE < size && 
				VM_PAGE_TO_PHYS(pages[i]) + GMEM_PAGE_SIZE == VM_PAGE_TO_PHYS(pages[i + 1]))
				++ i;
			// map pages[last_i], ..., pages[i]
			pmap->mmu_ops->mmu_pmap_enter(pmap, start + GMEM_PAGE_SIZE * last_i, 
				(i + 1 - last_i) * GMEM_PAGE_SIZE, VM_PAGE_TO_PHYS(pages[last_i]),
				prot, mem_flags);

			last_i = i + 1;
		}
	}
	else {
		for (i = 0; i < size / GMEM_PAGE_SIZE; i ++)
			pmap->mmu_ops->mmu_pmap_enter(pmap, start + GMEM_PAGE_SIZE * i, 
				GMEM_PAGE_SIZE, VM_PAGE_TO_PHYS(pages[i]), prot, mem_flags);
	}
	return GMEM_OK;
}

// eager device uses buffer granualrity so that we do not support split operations.
gmem_error_t gmem_uvas_unmap(dev_pmap_t *pmap, gmem_uvas_entry_t *entry, int wait,
	void (* unmap_callback)(void *), void *callback_args)
{
	KASSERT(pmap != NULL, ("The pmap to unmap is NULL!"));

	// I think there is no point to enqueue mmu_pmap_release operations from different pmap
	// It is also not common to see a lot of pmap_release operations from the same pmap
	// So just perform it directly?

	// Think about how to async?
	if (wait) {
		// The unmap will be sync
		pmap->mmu_ops->mmu_pmap_release(pmap, entry->start, entry->end - entry->start - pmap->uvas->format.guard);
		pmap->mmu_ops->mmu_tlb_invl(pmap, entry->start, entry->end - entry->start - pmap->uvas->format.guard);
		gmem_uvas_free_span(entry->uvas, entry);
	} else {
		// The unmap will be async
		// gmem_uvas_enqueue_unmap_request(pmap, entry);
	}

	return GMEM_OK;
}

gmem_error_t gmem_mmu_pmap_kill_generic(dev_pmap_t *pmap, struct gmem_uvas_entries_tailq *ext_entries) 
{
	gmem_uvas_entry_t *entry;
	TAILQ_FOREACH(entry, ext_entries, mapped_entry) {
		pmap->mmu_ops->mmu_pmap_release(pmap, entry->start, entry->end - entry->start - pmap->uvas->format.guard);
		pmap->mmu_ops->mmu_tlb_invl(pmap, entry->start, entry->end - entry->start - pmap->uvas->format.guard);
	}
	return GMEM_OK;
}

// munmap all for program termination or whatever.
gmem_error_t gmem_uvas_unmap_all(gmem_uvas_t *uvas, int wait,
	void (* unmap_callback)(void *), void *callback_args)
{
	GMEM_UVAS_LOCK(uvas);
	gmem_uvas_unmap_external(uvas, &uvas->mapped_entries, wait, unmap_callback, callback_args, false);
	GMEM_UVAS_UNLOCK(uvas);

	return GMEM_OK;
}

int unmap_coalesce_threshold = 1024;
int tlb_coalescing_threshold = 5;
int enable_daemon = 1;
int enable_async = 1;
int wakeup_time = 1; // 1 runs per 1 second
int instrument = 1;

static void gmem_uvas_generic_unmap_handler(gmem_uvas_t *uvas)
{
	dev_pmap_t *pmap;
	struct unmap_request *req, *req_tmp;
	gmem_uvas_entry_t *entry;

	UVAS_ASSERT_DEQUEUE_LOCKED(uvas);

	bool tlb_coalesce = uvas->unmap_working_pages >= tlb_coalescing_threshold ? true : false;
	// unmap all mmus
	TAILQ_FOREACH(pmap, &uvas->dev_pmap_header, unified_pmap_list) {
		TAILQ_FOREACH(req, &uvas->unmap_workspace, next) {
			entry = req->entry;
			pmap->mmu_ops->mmu_pmap_release(pmap, entry->start, entry->end - entry->start - uvas->format.guard);
			if (!tlb_coalesce)
				pmap->mmu_ops->mmu_tlb_invl(pmap, entry->start, entry->end - entry->start - uvas->format.guard);
		}
		if (tlb_coalesce)
			pmap->mmu_ops->mmu_tlb_invl_coalesced(pmap);
	}

	// free va space and process callbacks
	TAILQ_FOREACH_SAFE(req, &uvas->unmap_workspace, next, req_tmp) {
		if ((entry = req->entry) != NULL)
			gmem_uvas_free_span(entry->uvas, entry);
		if (req->cb != NULL)
			(*req->cb)(req->cb_args);
		TAILQ_REMOVE(&uvas->unmap_workspace, req, next);
		uma_zfree(gmem_uvas_unmap_requests_zone, req);
	}
	uvas->unmap_working_pages = 0;
}

static inline void refill_consumer(gmem_uvas_t *uvas)
{
	UVAS_ASSERT_DEQUEUE_LOCKED(uvas);
	UVAS_ASSERT_ENQUEUE_LOCKED(uvas);
	TAILQ_CONCAT(&uvas->unmap_workspace, &uvas->unmap_requests, next);
	uvas->unmap_working_pages += uvas->unmap_pages;
	uvas->unmap_pages = 0;
}

static inline void enqueue_unmap_req(
	gmem_uvas_t *uvas, 
	struct gmem_uvas_entries_tailq *ext_entries,
	void (* unmap_callback)(void *),
	void *callback_args,
	bool sleepable)
{
	struct unmap_request *req;
	gmem_uvas_entry_t *entry, *entry1;
	struct unmap_task_tailq request_q;
	int pages = 0;

	TAILQ_INIT(&request_q);
	TAILQ_FOREACH_SAFE(entry, ext_entries, mapped_entry, entry1) {
		req = uma_zalloc(gmem_uvas_unmap_requests_zone, sleepable? M_WAITOK:M_NOWAIT);
		TAILQ_REMOVE(ext_entries, entry, mapped_entry);
		req->entry = entry;
		req->cb = NULL;
		// req->cb_args = NULL;
		pages += (req->entry->end - req->entry->start - uvas->format.guard) >> GMEM_PAGE_SHIFT;
		TAILQ_INSERT_TAIL(&request_q, req, next);
	}
	req->cb = unmap_callback;
	req->cb_args = callback_args;

	UVAS_ENQUEUE_LOCK(uvas);
	uvas->unmap_pages += pages;
	TAILQ_CONCAT(&uvas->unmap_requests, &request_q, next);

	// If the producer queue is full, swap it to the consumer queue 
	if (uvas->unmap_pages > unmap_coalesce_threshold) {
		// Wait if there are pending consumer tasks
		UVAS_DEQUEUE_LOCK(uvas);

		// refill the consumer queue
		refill_consumer(uvas);

		// allow other threads to refill the producer queue
		UVAS_ENQUEUE_UNLOCK(uvas);

		// Someone has to process all the pending unmap requests, let's do it now.
		gmem_uvas_generic_unmap_handler(uvas);
		UVAS_DEQUEUE_UNLOCK(uvas);
	} else
		UVAS_ENQUEUE_UNLOCK(uvas);
}

// munmap all for program termination or whatever.
// ext_entries must not be accessed by anyone else
gmem_error_t gmem_uvas_unmap_external(gmem_uvas_t *uvas, struct gmem_uvas_entries_tailq *ext_entries, 
	int wait, void (* unmap_callback)(void *), void *callback_args, bool sleepable)
{
	gmem_uvas_entry_t *entry, *entry1;
	dev_pmap_t *pmap;
	if (wait || !enable_async) {
		// The termination will be sync
		TAILQ_FOREACH(pmap, &uvas->dev_pmap_header, unified_pmap_list)
			pmap->mmu_ops->mmu_pmap_kill(pmap, ext_entries);

		TAILQ_FOREACH_SAFE(entry, ext_entries, mapped_entry, entry1) {
			TAILQ_REMOVE(ext_entries, entry, mapped_entry);
			gmem_uvas_free_span(entry->uvas, entry);
		}
		if (unmap_callback != NULL)
			(*unmap_callback)(callback_args);
	} else {
		// The unmap will be async
		// printf("[unmap async] request enqueued to uvas %p\n", uvas);
		enqueue_unmap_req(uvas, ext_entries, unmap_callback, callback_args, sleepable);
	}
	return GMEM_OK;
}

// Force all enqueued unmap requests to be done, used as a barrier to flush async_unmap.
void gmem_uvas_drain_unmap_tasks(gmem_uvas_t *uvas)
{
	UVAS_ENQUEUE_LOCK(uvas);

	// If the producer queue is full, swap it to the consumer queue 
	if (uvas->unmap_pages > 0) {
		// Wait if there are pending consumer tasks
		UVAS_DEQUEUE_LOCK(uvas);

		// refill the consumer queue
		refill_consumer(uvas);

		// allow other threads to refill the producer queue
		UVAS_ENQUEUE_UNLOCK(uvas);

		// Someone has to process all the pending unmap requests, let's do it now.
		gmem_uvas_generic_unmap_handler(uvas);
		UVAS_DEQUEUE_UNLOCK(uvas);
	} else
		UVAS_ENQUEUE_UNLOCK(uvas);
}

gmem_error_t gmem_uvas_protect(gmem_uvas_t *uvas, vm_offset_t start,
	vm_size_t size, vm_prot_t new_protection)
{
	KASSERT(uvas != NULL, ("The uvas to mutate protection is NULL!"));

	return GMEM_OK;
}

// gmem_mmap_eager:
// The interface takes the allocated physical memory,
// and eagerly map these pages
// It includes: va allocation, physical preparation, virtual mapping creation
gmem_error_t
gmem_mmap_eager(gmem_uvas_t *uvas, dev_pmap_t *pmap, vm_offset_t *start, vm_offset_t size,
    u_int eflags, u_int flags, vm_page_t *ma, bool track, gmem_uvas_entry_t **entry_ret)
{
    gmem_uvas_entry_t *entry;
    int error;

    // Missing: entry->flags |= eflags;
    if (uvas == NULL)
        debug_printf("iommu ctx does not have a valid uvas\n");

    // The Original IOMMU driver uses GMEM_PAGE_SIZE in the neighbourhood to prevent DMA bugs
    // It is possible to add GMEM_PAGE_SIZE * 2 in the allocation request to simulate this behavior.
    if ((flags & GMEM_UVA_ALLOC_FIXED) == 0)
        error = gmem_uvas_alloc_span(uvas, start, size, GMEM_PROT_READ | GMEM_PROT_WRITE, 
            flags, &entry);
    else {
        error = gmem_uvas_alloc_span_fixed(uvas, *start, *start + size, GMEM_PROT_READ | GMEM_PROT_WRITE, 
            flags, &entry);
    }
    KASSERT(entry->end - entry->start == size + uvas->format.guard, ("inconsistent va allocation with guard\n"));

    // Failed to allocate VA space
    if (error) {
        printf("!!!!!!Failed va allocation, no mapping will be created\n");
        // Any states require reversing?
        return error;
    }

    // Track it in uvas->mapped_entries
	if (track) {
		GMEM_UVAS_LOCK(uvas);
		entry->flags |= GMEM_UVAS_ENTRY_TRACKED;
		TAILQ_INSERT_TAIL(&uvas->mapped_entries, entry, mapped_entry);
		GMEM_UVAS_UNLOCK(uvas);
	}

    // Who should consider multiple pmaps cases?
    error = gmem_uvas_prepare_and_map_pages_sg(pmap, entry->start,
        size, ma, eflags, ((flags & GMEM_MF_CANWAIT) != 0 ? GMEM_WAITOK : 0), (size >> pmap->min_sp_shift));

    if (error) {
        // There is no need to call iotlb inv
        // TODO: we always free the entry when we add back this iotlb inv in the future
        // TODO: replace with unload_entry, as the map function could fail in the middle.
        // iommu_domain_unload_entry(domain, entry, true);
        gmem_uvas_free_span(uvas, entry);
        return (error);
    }

    if (entry_ret != NULL)
        *entry_ret = entry;
    return (0);
}

static void
gmem_uvas_async_unmap(void *args)
{
	gmem_uvas_t *uvas = (gmem_uvas_t *)args;
	UVAS_ENQUEUE_LOCK(uvas);
	for (;;)
	{
		if (enable_daemon && uvas->unmap_pages > 0) {
			// refill the consumer queue
			UVAS_DEQUEUE_LOCK(uvas);
			refill_consumer(uvas);

			// Someone has to process all the pending unmap requests, let's do it now.
			UVAS_ENQUEUE_UNLOCK(uvas);
			gmem_uvas_generic_unmap_handler(uvas);
			UVAS_DEQUEUE_UNLOCK(uvas);
			UVAS_ENQUEUE_LOCK(uvas);
		}

		msleep(&uvas->async_unmap_proc, &uvas->enqueue_lock, 0,
		    "uvas", 1 * hz / wakeup_time);
	}
	UVAS_ENQUEUE_UNLOCK(uvas);
}

static void
gmem_uvas_async_unmap_start(gmem_uvas_t *uvas)
{
	int error;
	struct proc *p;
	// struct thread *td;

	printf("Creating daemon\n");
	error = kproc_create(&gmem_uvas_async_unmap, (void *) uvas, &p, 0, 0,
		"uvas");
	if (error)
		panic("uvas async daemon: error %d\n", error);
	// td = FIRST_THREAD_IN_PROC(p);
	// printf("Acquiring thread lock\n");
	// thread_lock(td);

	// /* We're an idle task, don't count us in the load. */
	// td->td_flags |= TDF_NOLOAD;
	// sched_class(td, PRI_IDLE);
	// sched_prio(td, PRI_MAX_IDLE);
	// sched_add(td, SRQ_BORING);
	// printf("Releasing thread lock\n");
	// thread_unlock(td);
	// printf("Done.\n");
}


// int unmap_coalesce_threshold = 1024
// int tlb_coalescing_threshold = 100;
// int enable_async = 1;
// int wakeup_time = 1; // 1 runs per 1 second
static SYSCTL_NODE(_vm, OID_AUTO, gmem, CTLFLAG_RD | CTLFLAG_MPSAFE,
    NULL, "");
SYSCTL_INT(_vm_gmem, OID_AUTO, unmap_coalesce_threshold, CTLFLAG_RWTUN,
    &unmap_coalesce_threshold, 0,
    "unmap requests coalescing threshold");
SYSCTL_INT(_vm_gmem, OID_AUTO, tlb_coalesce_threshold, CTLFLAG_RWTUN,
    &tlb_coalescing_threshold, 0,
    "TLB invl coalescing threshold");
SYSCTL_INT(_vm_gmem, OID_AUTO, enable_unmap_async, CTLFLAG_RWTUN,
    &enable_async, 0,
    "enable async unmap");
SYSCTL_INT(_vm_gmem, OID_AUTO, wakeup_time, CTLFLAG_RWTUN,
    &wakeup_time, 0,
    "async unmap wakeup frequency");
SYSCTL_INT(_vm_gmem, OID_AUTO, instrument, CTLFLAG_RWTUN,
    &instrument, 0,
    "instrumentation switch");
SYSCTL_INT(_vm_gmem, OID_AUTO, enable_daemon, CTLFLAG_RWTUN,
    &enable_daemon, 0,
    "async unmap daemon");