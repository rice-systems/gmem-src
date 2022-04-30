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
#include <sys/vmmeter.h>
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

#include <sys/module.h>

static MALLOC_DEFINE(M_IOMMU_TEST, "iommu_test", "IOMMU test pool");

static int map(struct dmar_domain *domain, vm_paddr_t start, vm_paddr_t size,
    vm_page_t *pages, uint64_t pflags, int flags, bool contig)
{
	vm_offset_t i, last_i = 0;
	int error;

	// coalesce mapping requests
	while(last_i * GMEM_PAGE_SIZE < size) {
		i = last_i;

		// advance when contiguous
		while((i + 1) * GMEM_PAGE_SIZE < size && 
			VM_PAGE_TO_PHYS(pages[i]) + GMEM_PAGE_SIZE == VM_PAGE_TO_PHYS(pages[i + 1]))
			++ i;

		// pmap->mmu_ops->prepare(VM_PAGE_TO_PHYS(pages[last_i]), (i + 1 - last_i) * GMEM_PAGE_SIZE);

		// map pages[last_i], ..., pages[i]
		error = domain_map_buf(domain, start + GMEM_PAGE_SIZE * last_i,
			(i + 1 - last_i) * GMEM_PAGE_SIZE, VM_PAGE_TO_PHYS(pages[last_i]),
			DMAR_PTE_R | DMAR_PTE_W, GMEM_WAITOK);

		if (error != 0)
			panic("domain_map_buf returns error: %d\n", error);

		last_i = i + 1;
	}
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
				return (*pte & ~pg_frame) + (va & pg_frame);
			}
			else
				pte = (dmar_pte_t *) PHYS_TO_DMAP(*pte & PG_FRAME);
		}
		else {
			printf("translation failed at lvl %d\n", lvl);
			return 0;
		}
		shift -= DMAR_NPTEPGSHIFT;
	}
	return 0;
}

static void
dmar_domain_destroy_fake(struct dmar_domain *domain)
{
	// if ((domain->flags & DMAR_DOMAIN_GAS_INITED) != 0)
	// 	dmar_gas_fini_domain(domain);
	// if ((domain->flags & DMAR_DOMAIN_PGTBL_INITED) != 0)
		domain_free_pgtbl(domain);
	// mtx_destroy(&domain->dmar->iommu.lock);
	free(domain->dmar, M_IOMMU_TEST);
	// mtx_destroy(&domain->lock);
	free(domain, M_IOMMU_TEST);
}

static struct dmar_domain *
dmar_domain_alloc_fake(bool id_mapped)
{
	struct dmar_unit *fake_dmar;
	struct dmar_domain *domain;
	int error, id, mgaw;

	id = 7;
	fake_dmar = malloc(sizeof(*fake_dmar), M_IOMMU_TEST, M_WAITOK | M_ZERO);
	// mtx_init(&fake_dmar->iommu.lock, "fake_dmar", NULL, MTX_DEF);

	domain = malloc(sizeof(*domain), M_IOMMU_TEST, M_WAITOK | M_ZERO);
	domain->domain = id;
	// mtx_init(&domain->lock, "fake_domain", NULL, MTX_DEF);
	domain->dmar = fake_dmar;

	/*
	 * For now, use the maximal usable physical address of the
	 * installed memory to calculate the mgaw on id_mapped domain.
	 * It is useful for the identity mapping, and less so for the
	 * virtualized bus address space.
	 */
	domain->end = id_mapped ? ptoa(Maxmem) : BUS_SPACE_MAXADDR;
	// magic number stolen from existing hardware
	fake_dmar->hw_cap = 0xd2008c20660462;
	mgaw = dmar_maxaddr2mgaw(fake_dmar, domain->end, !id_mapped);
	error = domain_set_agaw(domain, mgaw);
	if (error != 0)
		goto fail;
	if (!id_mapped)
		/* Use all supported address space for remapping. */
		domain->end = 1ULL << (domain->agaw - 1);

	// dmar_gas_init_domain(domain);
	// if (id_mapped) {
	// 	domain->pgtbl_obj = domain_get_idmap_pgtbl(domain,
	// 	    domain->end);
	// 	domain->flags |= DMAR_DOMAIN_IDMAP;
	// } else {
		error = domain_alloc_pgtbl(domain);
	// 	if (error != 0)
	// 		goto fail;
	// }
	return (domain);
// fail:
// 	dmar_domain_destroy_fake(domain);
// 	return (NULL);
}

static int verify_sp(vm_page_t *ma, unsigned long npages)
{
	struct dmar_domain *fake_domain;
	int pglvl, pgtb_cnt;
	vm_paddr_t va, va_start, pg0 = 1 << 12, pg1 = 1 << 21, pg2 = 1 << 30;
	vm_paddr_t size = npages << PAGE_SHIFT;
	int test_cases = 8;
	vm_paddr_t test_start[8] = {0, pg0, pg1, pg0 + pg1, pg2, pg0 + pg2,
		pg1 + pg2, pg0 + pg1 + pg2};

	uprintf("verification starts, # of page table pages: %d\n", dmar_tbl_pagecnt);
	fake_domain = dmar_domain_alloc_fake(false);
	pgtb_cnt = dmar_tbl_pagecnt;
	for (int i = 0; i < test_cases; i ++) {
		va_start = test_start[i];
		if (map(fake_domain, va_start, size, ma, 
			DMAR_PTE_R | DMAR_PTE_W, IOMMU_PGF_WAITOK, true)) {
			printf("error mapping buffer\n");
			return 1;
		}

		// verify mapping
		int pgcnt[3] = {0};
		int truth[3] = {0};
		va = va_start;
		for (int j = 0; j < npages; j ++) {
			if (x86_translate(fake_domain, va, &pglvl) != VM_PAGE_TO_PHYS(ma[j])) {
				printf("mapping verification failed, va 0x%lx, page #%d, translate 0x%lx, paddr 0x%lx\n",
					va, j, x86_translate(fake_domain, va, &pglvl), VM_PAGE_TO_PHYS(ma[j]));
				return 1;
			}
			else
				pgcnt[pglvl] ++;
			va += DMAR_PAGE_SIZE;
		}

		// calculate the expected # of superpages

		// 1GB superpages
		if ((va_start - VM_PAGE_TO_PHYS(ma[0]) & (pg2 - 1)) == 0)
			truth[2] = (rounddown2(va_start + size, pg2) - roundup2(va_start, pg2)) / pg0;

		// 2MB superpages
		if ((va_start - VM_PAGE_TO_PHYS(ma[0]) & (pg1 - 1)) == 0)
			truth[1] = (rounddown2(va_start + size, pg1) - roundup2(va_start, pg1)) / pg0;
		truth[1] -= truth[2];
		truth[0] = npages - truth[1] - truth[2];

		for (int lvl = 0; lvl < 3; lvl ++)
			if (truth[lvl] != pgcnt[lvl]) {
				printf("Superpage # is incorrect, test case %d, lvl %d, pgcnt %d, truth %d\n",
					i, lvl, pgcnt[lvl], truth[lvl]);
				break;
			}

		if (domain_unmap_buf(fake_domain, va_start, size)) {
			printf("error unmapping buffer\n");
			return 1;
		}
	}
	if (pgtb_cnt != dmar_tbl_pagecnt)
		uprintf("page table count inconsistent: old %d, new %d\n", pgtb_cnt, dmar_tbl_pagecnt);
	dmar_domain_destroy_fake(fake_domain);
	uprintf("verification exits, # of page table pages: %d\n", dmar_tbl_pagecnt);
	return 0;
}

static int bench(vm_page_t *ma, unsigned long npages)
{
	struct dmar_domain *fake_domain;
	int test_cases = 3, run = 30;
	vm_paddr_t va_start, pg0 = 1 << 12, pg1 = 1 << 21, pg2 = 1 << 30;
	vm_paddr_t maxsize = npages << PAGE_SHIFT, size, sizeshift;
	vm_paddr_t test_start[3] = {pg0, pg1, pg2};
	uint64_t delta, mean[3][34][2] = {{{0}}}, std[3][34][2] = {{{0}}}, sample[30][2];

	fake_domain = dmar_domain_alloc_fake(false);
	uprintf("benchmark starts, # of page table pages: %d\n", dmar_tbl_pagecnt);
	// size (8GB) : 1 << 30 << 3
	for (int i = 0; i < test_cases; i ++) {
		uprintf("bench case # %d\n", i);
		va_start = test_start[i];

		for (sizeshift = 12; sizeshift < 34; sizeshift ++) {

			size = 1ULL << sizeshift;
			if (size > maxsize)
				break;

			// always cold start
			for (int try = 0; try < run; try ++) {
				delta = rdtscp();
				if (map(fake_domain, va_start, size, ma, 
					DMAR_PTE_R | DMAR_PTE_W, IOMMU_PGF_WAITOK, true)) {
					uprintf("error mapping buffer\n");
					break;
				}
				sample[try][0] = rdtscp() - delta;

				delta = rdtscp();
				if (domain_unmap_buf(fake_domain, va_start, size)) {
					uprintf("error unmapping buffer\n");
					break;
				}
				sample[try][1] = rdtscp() - delta;

			}

			for (int k = 0; k < 2; k ++) {
				for (int try = 0; try < run; try ++) {
					mean[i][sizeshift][k] += sample[try][k];
					std[i][sizeshift][k] += sample[try][k] * sample[try][k];
				}
				mean[i][sizeshift][k] /= run;
				std[i][sizeshift][k] = std[i][sizeshift][k] / run - mean[i][sizeshift][k] * mean[i][sizeshift][k];
			}
		}
	}

	for (int k = 0; k < 2; k ++) {
		if (k == 0)
			uprintf("map latency:\n");
		else
			uprintf("unmap latency: \n");

		uprintf("mean:\n");
		for (int i = 0; i < 3; i ++) {
			for (int j = 12; j < 34; j ++)
				uprintf("%lu ", mean[i][j][k]);
			uprintf("\n");
		}
		uprintf("square:\n");
		for (int i = 0; i < 3; i ++) {
			for (int j = 12; j < 34; j ++)
				uprintf("%lu ", std[i][j][k]);
			uprintf("\n");
		}
	}

	dmar_domain_destroy_fake(fake_domain);
	uprintf("benchmark exits, # of page table pages: %d\n", dmar_tbl_pagecnt);
	return 0;
}

static int test_iommu(bool id_mapped)
{
	// test 8GB physical pages
	unsigned long npages = 8 * 512 * 512;
	// struct dmar_domain* fake_domain;
	vm_page_t m, *ma;
	vm_object_t object;
	vm_paddr_t high = 32ULL << 30;
	vm_paddr_t size = npages << PAGE_SHIFT;

	object = vm_pager_allocate(OBJT_PHYS, NULL, size * 2, 0, 0, NULL);
	VM_OBJECT_WLOCK(object);
	m = vm_page_alloc_contig(object, 0, VM_ALLOC_NORMAL | VM_ALLOC_NOBUSY,
		npages, 0, high, 1ULL << 30, 0, VM_MEMATTR_DEFAULT);
	VM_OBJECT_WUNLOCK(object);
	if (m != NULL) {
		ma = malloc(sizeof(vm_page_t) * npages, M_IOMMU_TEST, M_WAITOK | M_ZERO);
		for (int i = 0; i < npages; i ++) 
			ma[i] = &m[i];
	}
	else {
		printf("page allocation failed, test terminates\n");
		return -1;
	}

	if (!id_mapped)
		uprintf("testing dynamic page table\n");


	verify_sp(ma, npages);
	bench(ma, npages);

	free(ma, M_IOMMU_TEST);
	vm_object_deallocate(object);
	return 0;
}

static int test_event_handler(struct module *module,
	int event_type, void *arg) 
{
	int retval = 0;

	switch (event_type) {

		case MOD_LOAD:
			uprintf("iommu test started\n");
			test_iommu(false);
			break;

		case MOD_UNLOAD:
			uprintf("iommu test terminated\n");
			break;

		default:
			retval = EOPNOTSUPP;
			break;
	}

	return retval;
}

static moduledata_t test_data = {
    "intel_test",
    test_event_handler,
    NULL
};

DECLARE_MODULE(intel_test, test_data, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);