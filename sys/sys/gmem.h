/*-
 * 
 * This software was developed by Weixi Zhu <wxzhu@rice.edu>
 * for gmem project.
 *
 * GMEM is a generic memory management interface for CPU and devices
 * It currently only supports x86_64 platforms.
 *
 */

#ifndef _GMEM_H_
#define	_GMEM_H_

// Assumptions: 
// 	All MMUs share the same physical memory pool
//  As at current stage we only support EPT and IOMMU

typedef struct gmem_dev gmem_dev_t;
typedef struct gmem_devmap_info gmem_devmap_t;

typedef struct gmem_mmu_ops gmem_mmu_ops_t;
typedef struct gmem_vma_format gmem_vma_format_t;
typedef struct gmem_uvas gmem_uvas_t;
typedef struct gmem_uvas_entry gmem_uvas_entry_t;
typedef struct dev_pmap_replica dev_pmap_replica_t;
typedef struct dev_pmap dev_pmap_t;

typedef uint8_t gmem_error_t;

// GMEM ERROR Code
#define GMEM_OK			0x0
#define GMEM_ENOMEM 	0x1
#define GMEM_EOVERFLOW	0x2
#define GMEM_EINVALIDARGS 0x3


#define PRINTINFO  { printf("[%s] %s line #%d\n", __FILE__, __func__, __LINE__); }
#endif