/*-
 * 
 * This software was developed by Weixi Zhu <wxzhu@rice.edu>
 * for gmem project.
 *
 * GMEM is a generic memory management interface for CPU and devices
 * It currently only supports x86_64 platforms.
 *
 */

#ifndef _INTEL_IOMMU_H_
#define	_INTEL_IOMMU_H_

struct intel_iommu_dev_data
{
	bool id_mapped;
	struct dmar_unit *dmar;
	struct dmar_domain *domain;
};

// This is a redundant data structure.
struct intel_iommu_pgtable
{
	// some junk from dmar_domain, delete all the followings in the future
	int mgaw;			/* (c) Real max address width */
	int agaw;			/* (c) Adjusted guest address width */
	int pglvl;			/* (c) The pagelevel */
	int awlvl;			/* (c) The pagelevel as the bitmask,
					   to set in context entry */
	u_int batch_no;

	bool id_mapped;

	// hardware information, iommus could differ, so it is required
	struct dmar_unit *dmar;

	// process context information, delete if not required
	struct dmar_domain *domain;

	// real page table data
	vm_object_t pgtbl_obj;

	u_int flags;

	// The original iommu data structure is messy -- 
	//	domain contains both page table and address space data
	//  dmar contains async queues
	//  domain members use dmar lock???
};

typedef struct intel_iommu_dev_data intel_iommu_dev_data_t;
typedef struct intel_iommu_pgtable intel_iommu_pgtable_t;

// both identity mapping and normal mappings should be supported
extern gmem_mmu_ops_t intel_iommu_ops;


extern int
domain_map_buf_locked(struct dmar_domain *domain, vm_offset_t base,
    vm_offset_t size, vm_offset_t pa, uint64_t pflags, int flags)

extern int domain_unmap_buf_locked(struct dmar_domain *domain,
    iommu_gaddr_t base, iommu_gaddr_t size);

#endif