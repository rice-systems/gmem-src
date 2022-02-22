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
static gmem_error_t gmem_uvas_free_span(gmem_uvas_t *uvas, vm_offset_t start,
	vm_size_t size);

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

RB_GENERATE(gmem_uvas_entries_tree, gmem_uvas_entry, rb_entry,
    gmem_uvas_cmp_entries);

// Three modes to use uvas:
// 	1. private: pmap is NULL && replicate == false
//  2. shared: uvas and pmap are both not NULL, replicate == false
//  3. replicate: uvas and pmap are both not NULL, replicate == true
gmem_error_t gmem_uvas_create(gmem_uvas_t *uvas, vm_size_t size, gmem_dev_t *dev,
	dev_pmap_t *pmap, void *dev_data, bool replicate, bool need_partial_update)
{
	if (uvas == NULL)
	{
		KASSERT(pmap == NULL, "Creating a uvas with non-null pmap");
		KASSERT(data == NULL, "Creating a uvas with non-null dev-specific data");

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
		TAILQ_INSERT_TAIL(&uvas->dev_pmap_header, pmap, unified_pmap_list);
		uvas->need_partial_update = need_partial_update
		uvas->size = size;
		if (need_partial_update)
		{
			// Currently we use no quantum cache
			uvas->arena = vmem_create("uva", 0, rounddown(size, PAGE_SIZE),
				PAGE_SIZE, 0, M_WAITOK);
		}
		else
		{
			// TODO: RB-TREE
			// RB_INIT(uvas->rb_root);
		}
	}
	else
	{
		// attach dev and pmap to the uvas
		panic("Attaching to a uvas is not implemented");
	}
	return GMEM_OK;
}

gmem_error_t gmem_uvas_delete(gmem_uvas_t *uvas)
{
	KASSERT(uvas != NULL, "The uvas to be deleted is NULL!");

	// traverse all pmaps of the uvas and delete them

	// free the uvas
	return GMEM_OK;
}

static gmem_error_t gmem_uvas_alloc_span(gmem_uvas_t *uvas, vm_offset_t *start, 
	vm_size_t size, vm_prot_t protection, dev_pmap_t *pmap, 
	gmem_uvas_entry_t *entry)
{
	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
	if (uvas->need_partial_update)
	{
		// use rb-tree allocator
	}
	else
	{
		// use vmem allocator
	}
	return GMEM_OK;
}

static gmem_error_t gmem_uvas_free_span(gmem_uvas_t *uvas, vm_offset_t start,
	vm_size_t size)
{
	KASSERT(uvas != NULL, "The uvas to allocate entry is NULL!");
	if (uvas->need_partial_update)
	{
		// use rb-tree allocator
	}
	else
	{
		// use vmem allocator
	}
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