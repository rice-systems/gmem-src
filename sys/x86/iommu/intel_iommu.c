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
#include <dev/pci/pcireg.h>
#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/cpu.h>
#include <machine/md_var.h>
#include <machine/specialreg.h>
#include <x86/include/busdma_impl.h>
#include <dev/iommu/busdma_iommu.h>
#include <x86/iommu/intel_reg.h>
#include <x86/iommu/intel_dmar.h>

#include <sys/gmem.h>
#include <amd64/gmem/gmem_dev.h>
#include <amd64/gmem/gmem_uvas.h>
#include <x86/iommu/intel_iommu.h>

// dmar_domain_alloc ?
static gmem_error_t intel_iommu_pmap_create(dev_pmap_t *pmap, void *dev_data)
{
	intel_iommu_pgtable_t *pgtable;

	KASSERT(pmap->data == NULL, "creating a pmap over existing page table");
	pmap->data = dev_data;


	pgtable = pmap->data;
	if (pgtable->id_mapped) {
		if ((pgtable->dmar->hw_ecap & DMAR_ECAP_PT) == 0) {
			pgtable->domain->pgtbl_obj = domain_get_idmap_pgtbl(pgtable->domain,
			    pgtable->domain->iodom.end);
		}
		pgtable->domain->iodom.flags |= IOMMU_DOMAIN_IDMAP;
	} else {
		domain_alloc_pgtbl(pgtable->domain);
	}
	return GMEM_OK;
}

static gmem_error_t intel_iommu_pmap_destroy(dev_pmap_t *pmap)
{
	intel_iommu_pgtable_t *pgtable;

	pgtable = (intel_iommu_pgtable_t *) pmap->data;
	domain_free_pgtbl(pgtable->domain);
	return GMEM_OK;
}

static gmem_error_t intel_iommu_pmap_enter(dev_pmap_t *pmap, vm_offset_t va, vm_size_t size, 
	vm_paddr_t pa, u_int prot, u_int mem_flags)
{

	struct dmar_domain *domain;
	struct dmar_unit *unit;
	uint64_t pflags;
	int error;

	pflags = ((prot & IOMMU_MAP_ENTRY_READ) != 0 ? DMAR_PTE_R : 0) |
	    ((prot & IOMMU_MAP_ENTRY_WRITE) != 0 ? DMAR_PTE_W : 0) |
	    ((prot & IOMMU_MAP_ENTRY_SNOOP) != 0 ? DMAR_PTE_SNP : 0) |
	    ((prot & IOMMU_MAP_ENTRY_TM) != 0 ? DMAR_PTE_TM : 0);

	intel_iommu_pgtable_t *pgtable = pmap->data;
	domain = pgtable->domain;
	unit = domain->dmar;


	START_STATS;
	DMAR_DOMAIN_PGLOCK(domain);
	error = domain_map_buf_locked(domain, va, size, pa, pflags, mem_flags);
	DMAR_DOMAIN_PGUNLOCK(domain);
    FINISH_STATS(MAP, size >> 12);
	if (error != 0)
		return (error);

	if ((unit->hw_cap & DMAR_CAP_CM) != 0)
		domain_flush_iotlb_sync(domain, va, size);
	else if ((unit->hw_cap & DMAR_CAP_RWBF) != 0) {
		/* See 11.1 Write Buffer Flushing. */
		DMAR_LOCK(unit);
		dmar_flush_write_bufs(unit);
		DMAR_UNLOCK(unit);
	}

	return GMEM_OK;
}

static gmem_error_t intel_iommu_pmap_release(dev_pmap_t *pmap, vm_offset_t va, vm_size_t size)
{
	intel_iommu_pgtable_t *pgtable = pmap->data;
	int error;

	DMAR_DOMAIN_PGLOCK(pgtable->domain);
	error = domain_unmap_buf_locked(pgtable->domain, va, size);
	DMAR_DOMAIN_PGUNLOCK(pgtable->domain);

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