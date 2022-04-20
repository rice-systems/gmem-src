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

static vm_paddr_t x86_translate(struct dmar_domain *domain, vm_offset_t va, int *pglvl)
{
	int lvl, id, shift;
	vm_paddr_t pg_frame;
	shift = 12 + (domain->pglvl - 1) * 9;
	dmar_pte_t *pte = (dmar_pte_t *) PHYS_TO_DMAP(VM_PAGE_TO_PHYS(domain->pglv0));
	for (lvl = 0; lvl < domain->pglvl; lvl ++) {
		id = (va >> shift) & DMAR_PTEMASK;
		pte = &pte[id];
		if (*pte != 0) {
			if ((*pte & DMAR_PTE_SP) != 0 || lvl == domain->pglvl - 1) {
				pg_frame = (1ULL << shift) - 1;
				*pglvl = domain->pglvl - 1 - lvl;
				return *pte; // (*pte & ~pg_frame) + (va & pg_frame);
			}
			else
				pte = (dmar_pte_t *) PHYS_TO_DMAP(*pte & PG_FRAME);
		}
		else {
			// printf("translation failed at lvl %d\n", lvl);
			return 0;
		}
		shift -= DMAR_NPTEPGSHIFT;
	}
	return 0;
}

static gmem_error_t intel_iommu_pmap_enter(dev_pmap_t *pmap, vm_offset_t va, vm_size_t size, 
	vm_paddr_t pa, u_int prot, u_int mem_flags)
{

	struct dmar_domain *domain;
	struct dmar_unit *unit;
	uint64_t pflags;
	int error, pglvl;

	pflags = ((prot & IOMMU_MAP_ENTRY_READ) != 0 ? DMAR_PTE_R : 0) |
	    ((prot & IOMMU_MAP_ENTRY_WRITE) != 0 ? DMAR_PTE_W : 0) |
	    ((prot & IOMMU_MAP_ENTRY_SNOOP) != 0 ? DMAR_PTE_SNP : 0) |
	    ((prot & IOMMU_MAP_ENTRY_TM) != 0 ? DMAR_PTE_TM : 0);
	pflags = DMAR_PTE_R | DMAR_PTE_W;

	intel_iommu_pgtable_t *pgtable = pmap->data;
	domain = pgtable->domain;
	unit = domain->dmar;


	START_STATS;
	error = domain_map_buf(domain, va, size, pa, pflags, mem_flags);
    FINISH_STATS(MAP, size >> 12);
    if ((va <= 0x6d000 && 0x6d000 < va + size) || (va <= 0x6b000 && 0x6b000 < va + size)) {
    	printf("[intel_iommu.c] mapping va %lx - %lx, pte of 0x6b000 is %lx\n",
    		va, va + size, x86_translate(domain, 0x6b000, pglvl));
    }
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

	// destroy mappings
	START_STATS;
	error = domain_unmap_buf(pgtable->domain, va, size);
	FINISH_STATS(UNMAP, size >> 12);

	// invalidate TLB
	return GMEM_OK;
}

static gmem_error_t intel_iommu_pmap_protect(vm_offset_t va, vm_size_t size,
	vm_prot_t new_prot)
{
	return GMEM_OK;
}

static gmem_error_t intel_iommu_prepare(vm_paddr_t pa, vm_offset_t size)
{
	return GMEM_OK;
}

static gmem_error_t intel_iommu_init(struct gmem_mmu_ops* ops)
{
	if (atomic_cmpset_int(&ops->inited, 0, 1)) {
		printf("[intel_iommu_ops] initing\n");
		TAILQ_INIT(&ops->unmap_entries);
		mtx_init(&ops->lock, "mmu lock for global device data structures", NULL, MTX_DEF);
		ops->unmap_entry_cnt = 0;
	}
	return GMEM_OK;
}

static gmem_error_t intel_iommu_tlb_invl(dev_pmap_t *pmap, gmem_uvas_entry_t *entry)
{
	struct dmar_domain *domain = ((intel_iommu_pgtable_t *) pmap->data)->domain;
	struct dmar_unit *unit = ((intel_iommu_pgtable_t *) pmap->data)->dmar;

	if (!unit->qi_enabled) {
		domain_flush_iotlb_sync(domain, entry->start,
		    entry->end - entry->start);
	} else {
		DMAR_LOCK(unit);
		dmar_qi_invalidate_locked(domain, entry->start, entry->end -
		    entry->start,
		    true);
		DMAR_UNLOCK(unit);
	}
	return GMEM_OK;
}

// invalidate a list of mappings in a coalesced way
// static gmem_error_t intel_iommu_tlb_flush(struct gmem_uvas_entries_tailq *entries)
// {
// 	return GMEM_OK;
// }

gmem_mmu_ops_t intel_iommu_ops = {
	.pgsize_bitmap = (1UL << 12) | (1UL << 21) | (1UL << 30),
	.mmu_has_range_tlb = false,
	.inited = 0,
	.mmu_init = intel_iommu_init,
	.prepare = intel_iommu_prepare,
	.mmu_pmap_create = intel_iommu_pmap_create,
	.mmu_pmap_destroy = intel_iommu_pmap_destroy,
	.mmu_pmap_enter = intel_iommu_pmap_enter,
	.mmu_pmap_release = intel_iommu_pmap_release,
	.mmu_pmap_protect = intel_iommu_pmap_protect,
	.mmu_tlb_invl = intel_iommu_tlb_invl,
	.mmu_pmap_kill = gmem_mmu_pmap_kill_generic,
};