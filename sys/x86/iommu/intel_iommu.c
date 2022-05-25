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

#define domain_page_shift(domain, lvl) ((domain->pglvl - lvl - 1) * DMAR_NPTEPGSHIFT + DMAR_PAGE_SHIFT)
#define domain_pgtbl_pte_off(domain, base, lvl) (base >> (DMAR_PAGE_SHIFT + (domain->pglvl - lvl - 1) * DMAR_NPTEPGSHIFT) & DMAR_PTEMASK)

// There are no concurrent mapping/unmapping of the same PTE,
// so the lock only needs to protect page allocations of the iommu page table.
static int
domain_pmap_enter_locked(struct dmar_domain *domain, vm_offset_t base, 
    vm_offset_t size, vm_offset_t pa, uint64_t pflags, int flags, 
    int lvl, dmar_pte_t *ptep)
{
	vm_page_t m, pm;
	dmar_pte_t *pte;
	vm_offset_t pgshift, pg_size, pg_frame, end1, mapsize;
	int i, ret = 0;

	pm = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t) ptep));

	i = domain_pgtbl_pte_off(domain, base, lvl);
	pgshift = domain_page_shift(domain, lvl);
	pg_size = 1ULL << pgshift;
	pg_frame = pg_size - 1;

	while (size > 0) {
		pte = &ptep[i];

		// map the page, it could be a superpage
		if (lvl == domain->pglvl - 1) {
			*pte = pa | pflags;
finish:
			dmar_flush_pte_to_ram(domain->dmar, pte);
			pm->ref_count ++;
			size -= pg_size;
			pa += 1 << pgshift;
		} 
		else {
			// now determine the map size (base, mapsize)
			end1 = ((base >> pgshift) + 1) << pgshift;
			mapsize = (end1 <= base + size) ? end1 - base : size;

			// Can we map a superpage?
			if ((mapsize == pg_size) && ((base & pg_frame) == 0)
				&& ((pa & pg_frame) == 0)
				&& domain_is_sp_lvl(domain, lvl + 1)) {
				*pte = pa | pflags | DMAR_PTE_SP;
				base += mapsize;
				goto finish;
			}
			else {
				// do we need to create pg table page?
				if (*pte == 0) {
					m = dmar_pgalloc_null(i + (lvl << DMAR_NPTEPGSHIFT), 
						flags | IOMMU_PGF_ZERO);
					*pte = DMAR_PTE_R | DMAR_PTE_W | VM_PAGE_TO_PHYS(m);
					dmar_flush_pte_to_ram(domain->dmar, pte);
					pm->ref_count ++;
				}
				domain_pmap_enter_locked(domain, base, mapsize, 
						pa, pflags, flags, lvl + 1, 
						(dmar_pte_t*) PHYS_TO_DMAP(*pte & PG_FRAME));
				size -= mapsize;
				base += mapsize;
				pa += mapsize;
			}
		}
		i ++;
	}
	return ret;
}

// No need to consider demotion since it never splits mappings.
static int domain_pmap_release_locked(struct dmar_domain *domain, vm_offset_t base, 
    vm_offset_t size, int lvl, dmar_pte_t *ptep)
{
	vm_page_t pm;
	dmar_pte_t *pte;
	vm_offset_t pgshift, pg_size, pg_frame, end1, mapsize;
	int i;

	pm = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t) ptep));

	i = domain_pgtbl_pte_off(domain, base, lvl);
	pgshift = domain_page_shift(domain, lvl);
	pg_size = 1ULL << pgshift;
	pg_frame = pg_size - 1;

	while (size > 0) {
		pte = &ptep[i];
		if (lvl == domain->pglvl - 1 || (*pte & DMAR_PTE_SP) != 0) {
			mapsize = pg_size;
			// No need to consider splitting superpage mapping
		} else {
			end1 = ((base >> pgshift) + 1) << pgshift;
			mapsize = (end1 <= base + size) ? end1 - base : size;
			// Dig deeper
			if (domain_pmap_release_locked(domain, base, mapsize, lvl + 1, 
				(dmar_pte_t*) PHYS_TO_DMAP(*pte & PG_FRAME)))
				goto skip_clear;
		}
		*pte = 0;
		dmar_flush_pte_to_ram(domain->dmar, pte);
		pm->ref_count --;

skip_clear:

		size -= mapsize;
		base += mapsize;
		i ++;
	}

	if (pm->ref_count == 1) {
		dmar_pgfree_null(pm);
		return 0;
	}
	return 1;
}

// No consideration of sp promotions
int domain_pmap_enter_fast(struct dmar_domain *domain, vm_offset_t va, 
    vm_offset_t size, vm_offset_t pa, uint64_t pflags, int flags)
{
	int lvl;
	vm_page_t m; //, pm;
	dmar_pte_t *pte, *root = domain->root;
	int i;

	for (; size > 0; va += PAGE_SIZE, pa += PAGE_SIZE, size -= PAGE_SIZE) {
		pte = root;
		for (lvl = 0; lvl < domain->pglvl; lvl ++) {
			i = domain_pgtbl_pte_off(domain, va, lvl);
			// pm = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t) pte));
			pte = &pte[i];

			if (lvl < domain->pglvl - 1) {
				if (*pte == 0) {
					m = dmar_pgalloc_null(i + (lvl << DMAR_NPTEPGSHIFT), 
						flags | IOMMU_PGF_ZERO);
					if (atomic_cmpset_64(pte, 0, DMAR_PTE_R | DMAR_PTE_W | VM_PAGE_TO_PHYS(m))) {
						dmar_flush_pte_to_ram(domain->dmar, pte);
						// atomic_add_int(&pm->ref_count, 1);
					}
					else
						dmar_pgfree_null(m);
				}
				pte = (dmar_pte_t*) PHYS_TO_DMAP(*pte & PG_FRAME);
			}
			else
			{
				*pte = pa | pflags;
				dmar_flush_pte_to_ram(domain->dmar, pte);
				// atomic_add_int(&pm->ref_count, 1);
				// This is the point to insert promotion code, if pm->ref_count == 1 + 512
			}
		}
	}
	return 0;
}

// No need to consider demotion since it never splits mappings.
int domain_pmap_release_fast(struct dmar_domain *domain, vm_offset_t va, vm_offset_t size)
{
	int lvl;
	// vm_page_t pm;
	dmar_pte_t *pte, *root = domain->root;
	int i;

	for (; size > 0; va += PAGE_SIZE, size -= PAGE_SIZE) {
		pte = root;
		for (lvl = 0; lvl < domain->pglvl; lvl ++) {
			i = domain_pgtbl_pte_off(domain, va, lvl);
			// pm = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t) pte));
			pte = &pte[i];

			if (lvl < domain->pglvl - 1 && (*pte & DMAR_PTE_SP) == 0)
				pte = (dmar_pte_t*) PHYS_TO_DMAP(*pte & PG_FRAME);
			else
			{
				*pte = 0;
				dmar_flush_pte_to_ram(domain->dmar, pte);
				// atomic_add_int(&pm->ref_count, -1);
				// This is the point to insert demotion code, if DMAR_PTE_SP
			}
		}
	}
	return 0;
}

// No consideration of sp promotions
int domain_pmap_enter_fast_test(struct dmar_domain *domain, vm_offset_t va, 
    vm_offset_t size, vm_offset_t pa, uint64_t pflags, int flags)
{
	int lvl;
	vm_page_t m, p[4];
	dmar_pte_t *pte, *root = domain->root;
	int i;

	rw_rlock(&domain->lock);
	for (; size > 0; va += PAGE_SIZE, pa += PAGE_SIZE, size -= PAGE_SIZE) {
		pte = root;
		for (lvl = 0; lvl < domain->pglvl; lvl ++) {
			i = domain_pgtbl_pte_off(domain, va, lvl);
			p[lvl] = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t) pte));

			pte = &pte[i];

			if (lvl < domain->pglvl - 1) {
				if (*pte == 0) {
					m = dmar_pgalloc_null(i + (lvl << DMAR_NPTEPGSHIFT), 
						flags | IOMMU_PGF_ZERO);
					if (atomic_cmpset_64(pte, 0, DMAR_PTE_R | DMAR_PTE_W | VM_PAGE_TO_PHYS(m))) {
						dmar_flush_pte_to_ram(domain->dmar, pte);
						atomic_add_int(&p[lvl]->ref_count, 1);
					}
					else
						dmar_pgfree_null(m);
				}
				pte = (dmar_pte_t*) PHYS_TO_DMAP(*pte & PG_FRAME);
			}
			else
			{
				*pte = pa | pflags;
				dmar_flush_pte_to_ram(domain->dmar, pte);
				atomic_add_int(&p[lvl]->ref_count, 1);
				// This is the point to insert promotion code, if pm->ref_count == 1 + 512
			}
		}
	}
	rw_runlock(&domain->lock);
	return 0;
}

// No need to consider demotion since it never splits mappings.
int domain_pmap_release_fast_test(struct dmar_domain *domain, vm_offset_t va, vm_offset_t size)
{
	int lvl;
	vm_page_t p[4];
	dmar_pte_t *pte, *root = domain->root, *ptes[4];
	int i;

	for (; size > 0; va += PAGE_SIZE, size -= PAGE_SIZE) {
		pte = root;
		for (lvl = 0; lvl < domain->pglvl; lvl ++) {
			i = domain_pgtbl_pte_off(domain, va, lvl);
			p[lvl] = PHYS_TO_VM_PAGE(DMAP_TO_PHYS((vm_offset_t) pte));
			ptes[lvl] = pte;

			pte = &pte[i];

			if (lvl < domain->pglvl - 1 && (*pte & DMAR_PTE_SP) == 0)
				pte = (dmar_pte_t*) PHYS_TO_DMAP(*pte & PG_FRAME);
			else
			{
				*pte = 0;
				dmar_flush_pte_to_ram(domain->dmar, pte);
				atomic_add_int(&p[lvl]->ref_count, -1);
				// This is the point to insert demotion code, if DMAR_PTE_SP

				// This is the point we start to try to reclaim page table pages
				if (p[lvl]->ref_count == 1) {
					rw_wlock(&domain->lock);
					while(p[lvl]->ref_count == 1 && lvl > 0)
					{
						dmar_pgfree_null(p[lvl]);
						lvl --;
						*ptes[lvl] = 0;
						dmar_flush_pte_to_ram(domain->dmar, ptes[lvl]);
						atomic_add_int(&p[lvl]->ref_count, -1);
					}
					rw_wunlock(&domain->lock);
				}
				// we have reached the leaf node and we are done.
				break;
			}
		}
	}
	return 0;
}



// This function has been changed to map a contiguous pa range.
static inline int
domain_map_buf(struct dmar_domain *domain, vm_offset_t base,
    vm_offset_t size, vm_offset_t pa, uint64_t pflags, int flags)
{
	DMAR_DOMAIN_PGLOCK(domain);

	START_STATS;
	domain_pmap_enter_locked(domain, base, size, pa, pflags, flags, 
		0, (dmar_pte_t*) PHYS_TO_DMAP(VM_PAGE_TO_PHYS(domain->pglv0)));
    FINISH_STATS(_MAP, size >> 12);

	DMAR_DOMAIN_PGUNLOCK(domain);
	return 0;
}

static inline uint64_t
domain_wait_iotlb_flush(struct dmar_unit *unit, uint64_t wt, int iro)
{
	uint64_t iotlbr;

	dmar_write8(unit, iro + DMAR_IOTLB_REG_OFF, DMAR_IOTLB_IVT |
	    DMAR_IOTLB_DR | DMAR_IOTLB_DW | wt);
	for (;;) {
		iotlbr = dmar_read8(unit, iro + DMAR_IOTLB_REG_OFF);
		if ((iotlbr & DMAR_IOTLB_IVT) == 0)
			break;
		cpu_spinwait();
	}
	return (iotlbr);
}

void
domain_flush_iotlb_sync(struct dmar_domain *domain, iommu_gaddr_t base,
    iommu_gaddr_t size)
{
	struct dmar_unit *unit;
	iommu_gaddr_t isize;
	uint64_t iotlbr;
	int am, iro;

	unit = domain->dmar;
	KASSERT(!unit->qi_enabled, ("dmar%d: sync iotlb flush call",
	    unit->iommu.unit));
	iro = DMAR_ECAP_IRO(unit->hw_ecap) * 16;
	DMAR_LOCK(unit);
	if ((unit->hw_cap & DMAR_CAP_PSI) == 0 || size > 2 * 1024 * 1024) {
		iotlbr = domain_wait_iotlb_flush(unit, DMAR_IOTLB_IIRG_DOM |
		    DMAR_IOTLB_DID(domain->domain), iro);
		KASSERT((iotlbr & DMAR_IOTLB_IAIG_MASK) !=
		    DMAR_IOTLB_IAIG_INVLD,
		    ("dmar%d: invalidation failed %jx", unit->iommu.unit,
		    (uintmax_t)iotlbr));
	} else {
		for (; size > 0; base += isize, size -= isize) {
			am = calc_am(unit, base, size, &isize);
			dmar_write8(unit, iro, base | am);
			iotlbr = domain_wait_iotlb_flush(unit,
			    DMAR_IOTLB_IIRG_PAGE |
			    DMAR_IOTLB_DID(domain->domain), iro);
			KASSERT((iotlbr & DMAR_IOTLB_IAIG_MASK) !=
			    DMAR_IOTLB_IAIG_INVLD,
			    ("dmar%d: PSI invalidation failed "
			    "iotlbr 0x%jx base 0x%jx size 0x%jx am %d",
			    unit->iommu.unit, (uintmax_t)iotlbr,
			    (uintmax_t)base, (uintmax_t)size, am));
			/*
			 * Any non-page granularity covers whole guest
			 * address space for the domain.
			 */
			if ((iotlbr & DMAR_IOTLB_IAIG_MASK) !=
			    DMAR_IOTLB_IAIG_PAGE)
				break;
		}
	}
	DMAR_UNLOCK(unit);
}

void
domain_flush_iotlb_domain(struct dmar_domain *domain)
{
	struct dmar_unit *unit;
	uint64_t iotlbr;
	int iro;

	unit = domain->dmar;
	iro = DMAR_ECAP_IRO(unit->hw_ecap) * 16;
	DMAR_LOCK(unit);
	iotlbr = domain_wait_iotlb_flush(unit, DMAR_IOTLB_IIRG_DOM |
	    DMAR_IOTLB_DID(domain->domain), iro);
	DMAR_UNLOCK(unit);
}


// ------------------------------------------------------ //


// GMEM CBs
static gmem_error_t intel_iommu_pmap_create(dev_pmap_t *pmap, void *dev_data)
{
	intel_iommu_pgtable_t *pgtable;

	KASSERT(pmap->data == NULL, ("creating a pmap over existing page table"));
	pmap->data = dev_data;

	pmap->min_sp_shift = 21;
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
	error = domain_map_buf(domain, va, size, pa, pflags, mem_flags);
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
	struct dmar_domain *domain = pgtable->domain;
	int error;

	// destroy mappings
	START_STATS;
	DMAR_DOMAIN_PGLOCK(domain);
	error = domain_pmap_release_locked(domain, va, size, 0, (dmar_pte_t*) PHYS_TO_DMAP(VM_PAGE_TO_PHYS(domain->pglv0)));
	DMAR_DOMAIN_PGUNLOCK(domain);
	FINISH_STATS(UNMAP, size >> 12);

	// invalidate TLB
	return GMEM_OK;
}

static gmem_error_t intel_iommu_pmap_enter_fast(dev_pmap_t *pmap, vm_offset_t va, vm_size_t size, 
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
	error = domain_pmap_enter_fast_test(domain, va, size, pa, pflags, mem_flags);
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

static gmem_error_t intel_iommu_pmap_release_fast(dev_pmap_t *pmap, vm_offset_t va, vm_size_t size)
{
	intel_iommu_pgtable_t *pgtable = pmap->data;
	struct dmar_domain *domain = pgtable->domain;
	int error;

	// destroy mappings
	START_STATS;
	error = domain_pmap_release_fast_test(domain, va, size);
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
		TAILQ_INIT(&ops->unmap_entries);
		mtx_init(&ops->lock, "mmu lock for global device data structures", NULL, MTX_DEF);
		ops->unmap_entry_cnt = 0;
	}
	return GMEM_OK;
}

static void intel_iommu_tlb_invl(dev_pmap_t *pmap, gmem_uvas_entry_t *entry)
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
}

static inline void intel_iommu_tlb_inv_domain(dev_pmap_t *pmap)
{
	struct dmar_domain *domain = ((intel_iommu_pgtable_t *) pmap->data)->domain;

	if (!domain->dmar->qi_enabled) {
		domain_flush_iotlb_domain(domain);
	} else {
		dmar_qi_invalidate_domain(domain);
	}
}

static void intel_iommu_tlb_invl_coalesced(
	dev_pmap_t *pmap)
{
	intel_iommu_tlb_inv_domain(pmap);
}

gmem_mmu_ops_t intel_iommu_ops = {
	.pgsize_bitmap = (1UL << 12) | (1UL << 21) | (1UL << 30),
	.mmu_has_range_tlb = false,
	.inited = 0,
	.mmu_init               = intel_iommu_init,
	.prepare                = intel_iommu_prepare,
	.mmu_pmap_create        = intel_iommu_pmap_create,
	.mmu_pmap_destroy       = intel_iommu_pmap_destroy,
	.mmu_pmap_enter         = intel_iommu_pmap_enter_fast,
	.mmu_pmap_release       = intel_iommu_pmap_release_fast,
	.mmu_pmap_protect       = intel_iommu_pmap_protect,
	.mmu_tlb_invl           = intel_iommu_tlb_invl,
	.mmu_pmap_kill          = gmem_mmu_pmap_kill_generic,
	.mmu_tlb_invl_coalesced = intel_iommu_tlb_invl_coalesced,
};

gmem_mmu_ops_t intel_iommu_default_ops = {
	.pgsize_bitmap = (1UL << 12) | (1UL << 21) | (1UL << 30),
	.mmu_has_range_tlb = false,
	.inited = 0,
	.mmu_init               = intel_iommu_init,
	.prepare                = intel_iommu_prepare,
	.mmu_pmap_create        = intel_iommu_pmap_create,
	.mmu_pmap_destroy       = intel_iommu_pmap_destroy,
	// .mmu_pmap_enter         = intel_iommu_pmap_enter,
	// .mmu_pmap_release       = intel_iommu_pmap_release,
	.mmu_pmap_enter         = intel_iommu_pmap_enter_fast,
	.mmu_pmap_release       = intel_iommu_pmap_release_fast,
	.mmu_pmap_protect       = intel_iommu_pmap_protect,
	.mmu_tlb_invl           = intel_iommu_tlb_invl,
	.mmu_pmap_kill          = gmem_mmu_pmap_kill_generic,
	.mmu_tlb_invl_coalesced = intel_iommu_tlb_invl_coalesced,
};