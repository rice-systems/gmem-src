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
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/memdesc.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/rman.h>
#include <sys/sf_buf.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/vmem.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_map.h>
#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <x86/include/busdma_impl.h>
#include <x86/iommu/intel_reg.h>
#include <dev/iommu/busdma_iommu.h>
#include <dev/pci/pcireg.h>
#include <x86/iommu/intel_dmar.h>

#include <sys/gmem.h>
#include <amd64/gmem/gmem_dev.h>
#include <amd64/gmem/gmem_uvas.h>
#include <x86/iommu/intel_iommu.h>

static gmem_error_t intel_iommu_pmap_create(dev_pmap_t *pmap, void *dev_data)
{
	intel_iommu_pgtable_t *pgtable;
	vm_page_t m;

	KASSERT(pmap->data == NULL, "creating a pmap over existing page table");
	pmap->data = malloc(sizeof(intel_iommu_pgtable_t), M_DEVBUF, M_WAITOK | M_ZERO);


	pgtable = pmap->data;
	// TODO: equivalent semantic conversion first
	pgtable->pglvl = 4;
	pgtable->id_mapped = ((intel_iommu_pgtable_t *) dev_data)->id_mapped;
	pgtable->dmar = ((intel_iommu_pgtable_t *) dev_data)->dmar;
	pgtable->domain = ((intel_iommu_pgtable_t *) dev_data)->domain;
	pgtable->pgtbl_obj = vm_pager_allocate(OBJT_PHYS, NULL,
	    IDX_TO_OFF(pglvl_max_pages(pgtable->pglvl)), 0, 0, NULL);
	
	VM_OBJECT_WLOCK(pgtable->pgtbl_obj);
	m = dmar_pgalloc(pgtable->domain->pgtbl_obj, 0, DMAR_PGF_WAITOK |
	    DMAR_PGF_ZERO | DMAR_PGF_OBJL);
	/* No implicit free of the top level page table page. */
	m->wire_count = 1;
	VM_OBJECT_WUNLOCK(pgtable->pgtbl_obj);

	// DMAR_LOCK(domain->dmar);
	// domain->flags |= DMAR_DOMAIN_PGTBL_INITED;
	// DMAR_UNLOCK(domain->dmar);
	return GMEM_OK;
}

static gmem_error_t intel_iommu_pmap_destroy(dev_pmap_t *pmap)
{
	intel_iommu_pgtable_t *pgtable;
	vm_object_t obj;
	struct dmar_unit *dmar;
	struct dmar_domain *domain;
	vm_page_t m;

	pgtable = (intel_iommu_pgtable_t *) pmap->data;
	obj = pgtable->pgtbl_obj;
	dmar = pgtable->dmar;
	domain = pgtable->domain;

	if (obj == NULL) {
		KASSERT((domain->dmar->hw_ecap & DMAR_ECAP_PT) != 0 &&
		    (domain->flags & DMAR_DOMAIN_IDMAP) != 0,
		    ("lost pagetable object domain %p", domain));
		// return;
	}
	else
	{
		// We save all changes in the future after the conversion
		// Don't call this function with a lock state issued outside
		DMAR_DOMAIN_ASSERT_PGLOCKED(domain);
		// VM_OBJECT_WLOCK(obj);
		domain->pgtbl_obj = NULL;

		if ((domain->flags & DMAR_DOMAIN_IDMAP) != 0) {
			put_idmap_pgtbl(obj);
			domain->flags &= ~DMAR_DOMAIN_IDMAP;
			return GMEM_OK;
		}

		/* Obliterate wire_counts */
		for (m = vm_page_lookup(obj, 0); m != NULL; m = vm_page_next(m))
			m->wire_count = 0;
		VM_OBJECT_WUNLOCK(obj);
		vm_object_deallocate(obj);
	}
	return GMEM_OK;
}

static gmem_error_t intel_iommu_pmap_enter(vm_offset_t va, vm_size_t size, 
	vm_paddr_t pa, vm_prot_t protection)
{
	return GMEM_OK;
}

static gmem_error_t intel_iommu_pmap_release(vm_offset_t va, vm_size_t size)
{
	return GMEM_OK;
}

static gmem_error_t intel_iommu_pmap_protect(vm_offset_t va, vm_size_t size,
	vm_prot_t new_prot)
{
	return GMEM_OK;
}

gmem_mmu_ops_t intel_iommu_ops = {
	.pgsize_bitmap = (1UL << 12) | (1UL << 21) | (1UL << 30),
	.mmu_has_range_tlb = false,
	.mmu_pmap_create = intel_iommu_pmap_create,
	.mmu_pmap_destroy = intel_iommu_pmap_destroy,
	.mmu_pmap_enter = intel_iommu_pmap_enter,
	.mmu_pmap_release = intel_iommu_pmap_release,
	.mmu_pmap_protect = intel_iommu_pmap_protect,
};