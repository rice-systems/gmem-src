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

	// printf("Trying to allocate\n");
	// PRINTINFO;
	// printf("Allowed to sleep? %d\n", flags);
	res = uma_zalloc(gmem_uvas_entry_zone, ((flags & GMEM_WAITOK) !=
	    0 ? M_WAITOK : M_NOWAIT) | M_ZERO);
	if (res != NULL) {
		// printf("allocated succeeded\n");
		res->uvas = uvas;
		atomic_add_int(&uvas->entries_cnt, 1);
		// printf("done\n");
	}
	else
		printf("gmem_uvas_alloc_entry NOMEM\n");
	// PRINTINFO;
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

// Three modes to use uvas:
// 	1. private: pmap is NULL && replicate == false
//  2. shared: uvas and pmap are both not NULL, replicate == false
//  3. replicate: uvas and pmap are both not NULL, replicate == true
//     TODO: change this mode to share CPU vma, consider the opencl case.
//  lookup: faultable device requires looking up uvas entries 
gmem_error_t gmem_uvas_create(gmem_uvas_t **uvas_res, gmem_dev_t *dev,
	dev_pmap_t *pmap_to_share, void *dev_data, bool replicate, bool need_lookup,
	vm_offset_t alignment, vm_offset_t boundary, vm_offset_t size)
{
	PRINTINFO;
	gmem_uvas_t *uvas;
	if (*uvas_res == NULL)
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
		TAILQ_INIT(&uvas->uvas_entry_header);
		TAILQ_INIT(&uvas->dev_pmap_header);

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
			gmem_rb_init(uvas);
		}
		else
		{
			uvas->allocator = VMEM;
			// Currently we use no quantum cache
			uvas->arena = vmem_create("uva", 0, rounddown(size, alignment), alignment, 0, M_WAITOK);
		}
	}
	else
	{
		// attach dev and pmap to the uvas
		panic("Attaching to a uvas is not implemented");
	}
	*uvas_res = uvas;
	PRINTINFO;
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
	return GMEM_OK;
}

gmem_error_t gmem_uvas_alloc_span(gmem_uvas_t *uvas, 
	vm_offset_t *start, vm_size_t size, vm_prot_t protection, u_int flags, gmem_uvas_entry_t **ret)
{
	gmem_uvas_entry_t *entry;
	int error;

	// PRINTINFO;
	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
	entry = gmem_uvas_alloc_entry(uvas, (flags & GMEM_MF_CANWAIT) != 0 ? GMEM_WAITOK:0);
	// printf("gmem_uvas_alloc_entry \n");
	if (entry == NULL)
		return (GMEM_ENOMEM);

	// PRINTINFO;
	if (uvas->allocator == RBTREE)
	{
		// use rb-tree allocator
		// TODO: 
		// offset makes no sense. Upgrade it to fit page alignment in the future
		error = gmem_rb_find_space(uvas, size, 0, flags, entry);
		// printf("gmem_uvas_find_space \n");
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
		GMEM_UVAS_LOCK(uvas);
		error = vmem_alloc(uvas->arena, size, M_FIRSTFIT | ((flags & GMEM_MF_CANWAIT) != 0 ?
			M_WAITOK : M_NOWAIT), start);
		GMEM_UVAS_UNLOCK(uvas);
		if (error != 0)
			return error;
		else {
			entry->start = *start;
			entry->end = *start + size;
		}
	}
	if (ret != NULL)
		*ret = entry;
	return GMEM_OK;
}

gmem_error_t gmem_uvas_alloc_span_fixed(gmem_uvas_t *uvas, 
	vm_offset_t start, vm_offset_t end, vm_prot_t protection, u_int flags, gmem_uvas_entry_t **ret)
{
	gmem_uvas_entry_t *entry;
	int error;

	PRINTINFO;
	if (start >= end)
		return GMEM_EINVALIDARGS;
	
	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
	entry = gmem_uvas_alloc_entry(uvas, (flags & GMEM_MF_CANWAIT) != 0 ? GMEM_WAITOK:0);
	if (entry == NULL)
		return (GMEM_ENOMEM);

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
		// vm_offset_t new_start;
		// use vmem allocator
		GMEM_UVAS_LOCK(uvas);
		printf("VMEM xalloc with start %lx, end %lx\n", start, end);
		error = 0;
		// error = vmem_xalloc(uvas->arena, end - start, 0, 0, 0, start, end, 
		// 	M_FIRSTFIT | ((flags & GMEM_MF_CANWAIT) != 0 ? M_WAITOK : M_NOWAIT), &new_start);
		GMEM_UVAS_UNLOCK(uvas);
		// if (start != new_start) {
		// 	printf("VMEM xalloc failed with start %lx, end %lx, newstart %lx\n", start, end, new_start);
		// }
		if (error != 0)
			return error;
		else {
			entry->start = start;
			entry->end = end;
		}
	}
	if (ret != NULL)
		*ret = entry;
	return GMEM_OK;
}

gmem_error_t gmem_uvas_free_span(gmem_uvas_t *uvas, vm_offset_t start,
	vm_size_t size, gmem_uvas_entry_t *entry)
{
	PRINTINFO;
	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
	if (uvas == NULL) {
		printf("[gmem panic] uvas is null\n");
		return -1;
	}

	GMEM_UVAS_LOCK(uvas);
	if (uvas->allocator == RBTREE) {
		// use rb-tree allocator
		if (entry != NULL) {
			gmem_rb_remove(uvas, entry);
			gmem_uvas_free_entry(uvas, entry);
		} else {
			gmem_uvas_entry_t span;
			span.start = start;
			span.end = start + size;
			gmem_rb_free_span(uvas, &span);
		}
	}
	else if (uvas->allocator == VMEM) {
		if (entry != NULL) {
			vmem_free(uvas->arena, entry->start, entry->end - entry->start);
		} else {
			// TODO: remove this code and panic.
			// silently ignore
			printf("start %lx\n", start);
			printf("start %lx\n", size);
			printf("arena %p\n", uvas->arena);

			vmem_free(uvas->arena, start, size);
			printf("VMEM free for an arbitrary va span not implemented, must free a tracked va allocation\n");
		}
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