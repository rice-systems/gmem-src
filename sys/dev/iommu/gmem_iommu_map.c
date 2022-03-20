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
 * Gmem-basd Guest Address Space management.
 */

// TODO: This function should be ported as a gmem
// API, we need to make sure not to expose gmem's data
// structure outside.
int
gmem_iommu_map(struct iommu_domain *domain, gmem_uvas_t *uvas, dev_pmap_t *pmap, vm_offset_t *start, vm_offset_t size, int offset,
    u_int eflags, u_int flags, vm_page_t *ma, gmem_uvas_entry_t **entry_ret)
{
    gmem_uvas_entry_t *entry;
    int error;

    // Missing: entry->flags |= eflags;
    // printf("gmem map size: %lu\n", size);
    if (uvas == NULL)
        debug_printf("iommu ctx does not have a valid uvas\n");
    // else
    //  printf("domain entry count : %d\n", domain->uvas->entries_cnt);
    if ((flags & GMEM_UVA_ALLOC_FIXED) == 0)
        error = gmem_uvas_alloc_span(uvas, start, size, GMEM_PROT_READ | GMEM_PROT_WRITE, 
            flags, &entry);
    else {
        error = gmem_uvas_alloc_span_fixed(uvas, *start, *start + size, GMEM_PROT_READ | GMEM_PROT_WRITE, 
            flags, &entry);
    }
    PRINTINFO;

    KASSERT(error == GMEM_OK,
        ("unexpected error %d from gmem_uvas_alloc_span", error));

    // The uvas may allow a single pmap, multiple pmaps sharing the same, pmaps holding exclusive mappings
    // right now only consider the single pmap case.
    // TODO: use pmap->mmu_ops
    PRINTINFO;
    debug_printf("MAP VA %lx %lx\n", entry->start, entry->end);
    error = domain->ops->map(domain, entry->start,
        entry->end - entry->start, ma, eflags,
        ((flags & GMEM_MF_CANWAIT) != 0 ?  GMEM_WAITOK : 0));

    PRINTINFO;
    if (error == ENOMEM) {
        // There is no need to call iotlb inv
        // TODO: we always free the entry when we add back this iotlb inv in the future
        // TODO: replace with unload_entry, as the map function could fail in the middle.
        // iommu_domain_unload_entry(entry, true);
        gmem_uvas_free_span(uvas, *start, size, entry);
        return (error);
    }
    KASSERT(error == 0,
        ("unexpected error %d from domain_map_buf", error));

    if (entry_ret != NULL)
        *entry_ret = entry;
    return (0);
}
