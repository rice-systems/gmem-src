/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2013 The FreeBSD Foundation
 * All rights reserved.
 *
 * This software was developed by Konstantin Belousov <kib@FreeBSD.org>
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

// #define	RB_AUGMENT(entry) iommu_gas_augment_entry(entry)

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/bus.h>
#include <sys/interrupt.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/memdesc.h>
#include <sys/mutex.h>
#include <sys/sysctl.h>
#include <sys/rman.h>
#include <sys/taskqueue.h>
#include <sys/tree.h>
#include <sys/uio.h>
#include <sys/vmem.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/uma.h>
#include <dev/pci/pcireg.h>
#include <dev/pci/pcivar.h>
#include <dev/iommu/iommu.h>
#include <dev/iommu/iommu_gas.h>
#include <dev/iommu/iommu_msi.h>
#include <machine/atomic.h>
#include <machine/bus.h>
#include <machine/md_var.h>
#include <machine/iommu.h>
#include <dev/iommu/busdma_iommu.h>
#include <sys/gmem.h>
#include <amd64/gmem/gmem_dev.h>
#include <amd64/gmem/gmem_uvas.h>
#include <x86/iommu/intel_iommu.h>

/*
 * Guest Address Space management.
 */

void
iommu_unmap_msi(struct iommu_ctx *ctx)
{
	struct gmem_uvas_entry *entry;
	struct iommu_domain *domain;

	domain = ctx->domain;
	entry = domain->msi_entry;
	if (entry == NULL)
		return;

	domain->ops->unmap(domain, entry->start, entry->end -
	    entry->start, IOMMU_PGF_WAITOK);

	// IOMMU_DOMAIN_LOCK(domain);
	// iommu_gas_free_space(domain, entry);
	// IOMMU_DOMAIN_UNLOCK(domain);

	// iommu_gas_free_entry(domain, entry);
	gmem_uvas_free_span(domain->uvas, entry->start, entry->end - entry->start, entry);

	domain->msi_entry = NULL;
	domain->msi_base = 0;
	domain->msi_phys = 0;
}

int
iommu_map_msi(struct iommu_ctx *ctx, iommu_gaddr_t size,
    u_int eflags, u_int flags, vm_page_t *ma)
{
	struct iommu_domain *domain;
	struct gmem_uvas_entry *entry;
	int error;
	vm_offset_t start;

	error = 0;
	domain = ctx->domain;

	/* Check if there is already an MSI page allocated */
	IOMMU_DOMAIN_LOCK(domain);
	entry = domain->msi_entry;
	IOMMU_DOMAIN_UNLOCK(domain);

	if (entry == NULL) {
        // TODO: use dev_pmap_t *pmap
		error = gmem_iommu_map(domain, domain->uvas, NULL, &start, size,
		    eflags, flags | GMEM_UVA_ALLOC, ma, &entry);

		IOMMU_DOMAIN_LOCK(domain);
		if (error == 0) {
			if (domain->msi_entry == NULL) {
				MPASS(domain->msi_base == 0);
				MPASS(domain->msi_phys == 0);

				domain->msi_entry = entry;
				domain->msi_base = entry->start;
				domain->msi_phys = VM_PAGE_TO_PHYS(ma[0]);
			} else {
				/*
				 * We lost the race and already have an
				 * MSI page allocated. Free the unneeded entry.
				 */
				gmem_uvas_free_entry(domain->uvas, entry);
			}
		} else if (domain->msi_entry != NULL) {
			/*
			 * The allocation failed, but another succeeded.
			 * Return success as there is a valid MSI page.
			 */
			error = 0;
		}
		IOMMU_DOMAIN_UNLOCK(domain);
	}

	return (error);
}

void
iommu_translate_msi(struct iommu_domain *domain, uint64_t *addr)
{

	*addr = (*addr - domain->msi_phys) + domain->msi_base;

	KASSERT(*addr >= domain->msi_entry->start,
	    ("%s: Address is below the MSI entry start address (%jx < %jx)",
	    __func__, (uintmax_t)*addr, (uintmax_t)domain->msi_entry->start));

	KASSERT(*addr + sizeof(*addr) <= domain->msi_entry->end,
	    ("%s: Address is above the MSI entry end address (%jx < %jx)",
	    __func__, (uintmax_t)*addr, (uintmax_t)domain->msi_entry->end));
}

// int
// iommu_map_region(struct iommu_domain *domain, struct iommu_map_entry *entry,
//     u_int eflags, u_int flags, vm_page_t *ma)
// {
// 	int error;

// 	error = iommu_gas_map_region(domain, entry, eflags, flags, ma);

// 	return (error);
// }

SYSCTL_NODE(_hw, OID_AUTO, iommu, CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, "");

#ifdef INVARIANTS
SYSCTL_INT(_hw_iommu, OID_AUTO, check_free, CTLFLAG_RWTUN,
    &iommu_check_free, 0,
    "Check the GPA RBtree for free_down and free_after validity");
#endif
