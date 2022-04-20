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

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

#include <sys/gmem.h>
#include <amd64/gmem/gmem_dev.h>
#include <amd64/gmem/gmem_uvas.h>
#include <amd64/gmem/gmem_rb_tree.h>

static uma_zone_t gmem_uvas_entry_zone;

static void
gmem_uvas_zone_init(void)
{

	gmem_uvas_entry_zone = uma_zcreate("GMEM_UVAS_ENTRY",
	    sizeof(struct gmem_uvas_entry), NULL, NULL,
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
	atomic_subtract_int(&uvas->entries_cnt, 1);
	uma_zfree(gmem_uvas_entry_zone, entry);
}

// Four modes to use uvas:
// 	1. private: pmap is NULL && replicate == false
//  2. shared: uvas and pmap are both not NULL, replicate == false
//  3. replicate: uvas and pmap are both not NULL, replicate == true
//  4. unique: the device is an edge device and the uvas has a single pmap
//     TODO: change this mode to share CPU vma, consider the opencl case.
//  lookup: faultable device requires looking up uvas entries 
gmem_error_t gmem_uvas_create(gmem_uvas_t **uvas_res, dev_pmap_t **pmap_res, gmem_dev_t *dev,
	dev_pmap_t *pmap_to_share, void *dev_data, int mode,
	vm_offset_t alignment, vm_offset_t boundary, vm_offset_t size)
{
	gmem_uvas_t *uvas;
	printf("[GMEM] creating uvas here, are we fucked up ?\n");
	if (*uvas_res == NULL && mode == GMEM_UVAS_UNIQUE)
	{
		KASSERT(pmap_to_share == NULL, "Creating a uvas with non-null pmap");
		KASSERT(dev_data == NULL, "Creating a uvas with non-null dev-specific data");

		// allocate and create the pmap with dev->mmu_ops
		dev_pmap_t *pmap = (dev_pmap_t *) malloc(sizeof(dev_pmap_t), M_DEVBUF, M_WAITOK | M_ZERO);
		// allocate and create the uvas
		uvas = (gmem_uvas_t *) malloc(sizeof(gmem_uvas_t), M_DEVBUF, M_WAITOK | M_ZERO);
		mtx_init(&uvas->lock, "uvas", NULL, MTX_DEF);

		// initialize pmap
		pmap->ndevices = 1;
		TAILQ_INIT(&pmap->gmem_dev_header);
		TAILQ_INSERT_TAIL(&pmap->gmem_dev_header, dev, gmem_dev_list);
		pmap->mmu_ops = dev->mmu_ops;
		pmap->pmap_replica = NULL;
		pmap->uvas = uvas;

		// use mmu callback to initialize device-specific data
		pmap->mmu_ops->mmu_pmap_create(pmap, dev_data);

		// initialize uvas
		TAILQ_INIT(&uvas->mapped_entries);
		TAILQ_INIT(&uvas->unmap_queue);
		TAILQ_INIT(&uvas->dev_pmap_header);

		// insert pmap to uvas pmap list
		TAILQ_INSERT_TAIL(&uvas->dev_pmap_header, pmap, unified_pmap_list);

		// insert pmap to dev pmap list
		// I don't think that this is necessary.
		// TODO: consider delete pmap field in gmem_dev

		uvas->format.alignment = alignment;
		uvas->format.boundary = boundary;
		uvas->format.maxaddr = size;

		// Edge device does not need to perform page faults
		if (0) {
			uvas->allocator = RBTREE;
			// TODO: RB-TREE
			gmem_rb_init(uvas);
		} else {
			uvas->allocator = VMEM;
			// Currently we use the maximum available quantum cache (16)
			uvas->arena = vmem_create("uva", 0, rounddown(size, alignment), 
				alignment, alignment * 16, M_WAITOK | M_FIRSTFIT);
		}

		*uvas_res = uvas;
		*pmap_res = pmap;
	}
	else
	{
		// attach dev and pmap to the uvas
		panic("Other UVAS modes are not implemented");
	}
	printf("Done with UVAS creating\n");
	return GMEM_OK;
}

gmem_error_t gmem_uvas_delete(gmem_uvas_t *uvas)
{
	KASSERT(uvas != NULL, "The uvas to be deleted is NULL!");

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

gmem_error_t gmem_uvas_alloc_span(gmem_uvas_t *uvas, 
	vm_offset_t *start, vm_size_t size, vm_prot_t protection, u_int flags, gmem_uvas_entry_t **ret)
{
	gmem_uvas_entry_t *entry;
	int error;

	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
	entry = gmem_uvas_alloc_entry(uvas, (flags & GMEM_MF_CANWAIT) != 0 ? GMEM_WAITOK:0);
	if (entry == NULL)
		return (GMEM_ENOMEM);

	START_STATS;
	if (uvas->allocator == RBTREE)
	{
		// use rb-tree allocator
		// TODO: offset makes no sense. (Offset is effectively a bug.)
		error = gmem_rb_find_space(uvas, size, flags, entry);
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
		error = vmem_alloc(uvas->arena, size, M_FIRSTFIT | ((flags & GMEM_MF_CANWAIT) != 0 ?
			M_WAITOK : M_NOWAIT), start);
		if (error != 0)
			return error;
		else {
			entry->start = *start;
			entry->end = *start + size;
		}
	}
    FINISH_STATS(VA_ALLOC, size >> 12);

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
		printf("Trying to allocate an invalid va span, start %lx end %lx\n", start, end);
		return GMEM_EINVALIDARGS;
	}
	
	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
	entry = gmem_uvas_alloc_entry(uvas, (flags & GMEM_MF_CANWAIT) != 0 ? GMEM_WAITOK:0);
	if (entry == NULL)
		return (GMEM_ENOMEM);

	START_STATS;
	if (uvas->allocator == RBTREE)
	{
		// use rb-tree allocator
		error = gmem_rb_reserve_region(uvas, start, end, entry);
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
		error = vmem_xalloc(uvas->arena, end - start, 0, 0, 0, start, end, 
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
			entry->end = end;
			entry->flags |= GMEM_UVAS_VMEM_XALLOC;
		}
	}
    FINISH_STATS(VA_ALLOC, (end - start) >> 12);

	if (ret != NULL)
		*ret = entry;
	return GMEM_OK;
}

gmem_error_t gmem_uvas_free_span(gmem_uvas_t *uvas, gmem_uvas_entry_t *entry)
{
	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
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
	FINISH_STATS(VA_FREE, (entry->end - entry->start) >> 12);
	return GMEM_OK;
}

gmem_error_t gmem_uvas_map_pages(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, vm_page_t first_page, u_int prot, u_int mem_flags)
{
	KASSERT(pmap != NULL, "The pmap to map is NULL!");

	if (size & PAGE_MASK)
		return GMEM_EINVALIDARGS;
	pmap->mmu_ops->mmu_pmap_enter(pmap, start, size, VM_PAGE_TO_PHYS(first_page),
		prot, mem_flags);
	return GMEM_OK;
}

// Map a list of scattered 4KB pages
// protection flags are required since a RO mapping can still be created with write permission
// memory flags are required because the device may ask the kernel to manage its physical memory
// mapping requires allocating physical pages.
// This interface automatically coalesce contiguous scattered pages.
static inline gmem_error_t gmem_uvas_prepare_and_map_pages_sg(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, vm_page_t *pages, u_int prot, u_int mem_flags)
{
	vm_offset_t i, last_i = 0;

	if (pmap == NULL || size < GMEM_PAGE_SIZE)
		return GMEM_EINVALIDARGS;

	// coalesce mapping requests
	while(last_i * GMEM_PAGE_SIZE < size) {
		i = last_i;

		// advance when contiguous
		while((i + 1) * GMEM_PAGE_SIZE < size && 
			VM_PAGE_TO_PHYS(pages[i]) + GMEM_PAGE_SIZE == VM_PAGE_TO_PHYS(pages[i + 1]))
			++ i;

		// pmap->mmu_ops->prepare(VM_PAGE_TO_PHYS(pages[last_i]), (i + 1 - last_i) * GMEM_PAGE_SIZE);

		// map pages[last_i], ..., pages[i]
		pmap->mmu_ops->mmu_pmap_enter(pmap, start + GMEM_PAGE_SIZE * last_i, 
			(i + 1 - last_i) * GMEM_PAGE_SIZE, VM_PAGE_TO_PHYS(pages[last_i]),
			prot, mem_flags);

		last_i = i + 1;
	}
	return GMEM_OK;
}

// eager device uses buffer granualrity so that we do not support split operations.
gmem_error_t gmem_uvas_unmap(dev_pmap_t *pmap, gmem_uvas_entry_t *entry, int wait,
	void (* unmap_callback(void *)), void *callback_args)
{
	KASSERT(pmap != NULL, "The pmap to unmap is NULL!");

	// I think there is no point to enqueue mmu_pmap_release operations from different pmap
	// It is also not common to see a lot of pmap_release operations from the same pmap
	// So just perform it directly?

	// Think about how to async?
	if (wait) {
		// The unmap will be sync
		pmap->mmu_ops->mmu_pmap_release(pmap, entry->start, entry->end - entry->start);
		pmap->mmu_ops->mmu_tlb_invl(pmap, entry);
		gmem_uvas_free_span(entry->uvas, entry);
	} else {
		// The unmap will be async
		// gmem_uvas_enqueue_unmap_request(pmap, entry);
	}

	return GMEM_OK;
}

gmem_error_t gmem_mmu_pmap_kill_generic(dev_pmap_t *pmap, struct gmem_uvas_entries_tailq *ext_entries) 
{
	gmem_uvas_entry_t *entry, *entry1;
	TAILQ_FOREACH_SAFE(entry, ext_entries, mapped_entry, entry1) {
		TAILQ_REMOVE(entries, entry, mapped_entry);

		pmap->mmu_ops->mmu_pmap_release(pmap, entry->start, entry->end - entry->start);
		pmap->mmu_ops->mmu_tlb_invl(pmap, entry);
		gmem_uvas_free_span(entry->uvas, entry);
	}
	return GMEM_OK;
}

// munmap all for program termination or whatever.
gmem_error_t gmem_uvas_unmap_all(dev_pmap_t *pmap, int wait,
	void (* unmap_callback(void *)), void *callback_args)
{
	GMEM_UVAS_LOCK(pmap->uvas);
	gmem_uvas_unmap_external(pmap, pmap->uvas->mapped_entries, wait, unmap_callback, callback_args);
	GMEM_UVAS_UNLOCK(pmap->uvas);

	return GMEM_OK;
}

// munmap all for program termination or whatever.
gmem_error_t gmem_uvas_unmap_external(dev_pmap_t *pmap, struct gmem_uvas_entries_tailq *ext_entries, 
	int wait, void (* unmap_callback(void *)), void *callback_args)
{
	if (wait) {
		// The termination will be sync
		pmap->mmu_ops->mmu_pmap_kill(pmap, ext_entries);
	} else {
		// The unmap will be async
		GMEM_UVAS_LOCK(pmap->uvas);
		TAILQ_CONCAT(&pmap->uvas->unmap_queue, ext_entries, mapped_entry);
		GMEM_UVAS_UNLOCK(pmap->uvas);
	}
	return GMEM_OK;
}

gmem_error_t gmem_uvas_protect(gmem_uvas_t *uvas, vm_offset_t start,
	vm_size_t size, vm_prot_t new_protection)
{
	KASSERT(uvas != NULL, "The uvas to mutate protection is NULL!");

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
        entry->end - entry->start, ma, eflags, ((flags & GMEM_MF_CANWAIT) != 0 ? GMEM_WAITOK : 0));

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