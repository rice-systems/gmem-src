/*-
 * 
 * This software was developed by Weixi Zhu <wxzhu@rice.edu>
 * for gmem project.
 *
 * GMEM is a generic memory management interface for CPU and devices
 * It currently only supports x86_64 platforms.
 *
 */

#ifndef _GMEM_UVAS_H_
#define	_GMEM_UVAS_H_

struct gmem_mmu_ops
{
	// bitmap of available page shifts for page-based TLB
	unsigned long pgsize_bitmap;
	bool mmu_has_range_tlb;

	// device page/range table creation and destruction.
	gmem_error_t (*mmu_pmap_create)(dev_pmap_t *pmap, void *dev_data);
	gmem_error_t (*mmu_pmap_destroy)(dev_pmap_t *pmap);

	// device mapping creation, manipulation and destruction
	// We do not include batching mechanism here, as we will not exercise
	// any throughput devices at this moment
	// We also do not include async version for map, as it will not be used
	gmem_error_t (*mmu_pmap_enter)(vm_offset_t va, vm_size_t size, 
		vm_paddr_t pa, vm_prot_t protection);
	gmem_error_t (*mmu_pmap_release)(vm_offset_t va, vm_size_t size);
	gmem_error_t (*mmu_pmap_protect)(vm_offset_t va, vm_size_t size,
		vm_prot_t new_prot);
};

RB_HEAD(gmem_uvas_entries_tree, gmem_uvas_entry);
RB_PROTOTYPE(gmem_uvas_entries_tree, gmem_uvas_entry, rb_entry,
    gmem_uvas_cmp_entries);

struct gmem_uvas // VM counterpart: struct vm_map
{
	// List of mapped entries
	TAILQ_HEAD(gmem_uvas_entry_tailq, gmem_uvas_entry) uvas_entry_header;

	// Whether this uvas needs partial update of its entries
	// 	This determines whether it uses vmem or rb-tree to allocate/free 
	//  uvas entries.
	bool need_partial_update;

	// uva arena for va allocation
	// We have to use a rb tree entry to support split/merge
	// but we may use vmem as well to allocate va span quickly
	vmem_t *arena;

	// Number of entires
	uint32_t nentries;

	// virtual size
	vm_size_t size;

	// A uvas may be used by multiple pmaps (mmus)
	TAILQ_HEAD(dev_pmap_tailq, dev_pmap) dev_pmap_header;

	struct gmem_uvas_entries_tree rb_root;
};

// split and merge may be applied if protection or vm_ops change
struct gmem_uvas_entry // VM counterpart: struct vm_map_entry
{
	vm_offset_t start;
	vm_offset_t end;

	vm_object_t object;	/* the vm object this entry point to */
	vm_ooffset_t offset;		/* offset into object */

	// May skip it if we use vmem to allocate/free va
	vm_size_t max_free;

	// a doubly linked list of entries sorted by base
	TAILQ_ENTRY(gmem_uvas_entry) mapped_entry;

	// rb-tree entry for query/delete/insert
	RB_ENTRY(gmem_uvas_entry) rb_entry;

	// changes of protection or pmap may result in splitting or merging
	vm_prot_t protection;
};

// A collection of pmaps that are registed in replication mode for a uvas
// devices of the pmap must come from the same NUMA group
// Well, at this moment all pmap come from a single NUMA group.
struct dev_pmap_replica
{
	uint8_t npmaps;
	struct dev_pmap **replicated_pmaps;
};

// device-dependent mapping data
// A pmap is coupled with an mmu instance
struct dev_pmap
{
	// An array of the mapping devices
	uint8_t ndevices;
	// for convenience, use a tailq for devices sharing this dev_pmap
	TAILQ_HEAD(gmem_dev_tailq, gmem_dev) gmem_dev_header;

	struct dev_pmap_replica *pmap_replica;

	// A pointer to its unified address space
	struct gmem_uvas *uvas;

	// list of pmaps included by a uvas
	TAILQ_ENTRY(dev_pmap) unified_pmap_list;

	// MMU ops to mutate the pmap. 
	// TO Think:
	// 1. Could it change dynamically?
	// 2. What happens when multiple devices share the same type of mmu?
	struct gmem_mmu_ops *mmu_ops;

	// Device-specific page table data to be operated by gmem_mmu_ops
	// can include a child_pmap for nested translation
	// can also store the implementation of mmu_ops
	void *data;
};

gmem_error_t gmem_uvas_create(gmem_uvas_t *uvas, vm_size_t size, gmem_dev_t *dev,
	dev_pmap_t *pmap, void *dev_data, bool replicate, bool need_partial_update);
gmem_error_t gmem_uvas_delete(gmem_uvas_t *uvas);
gmem_error_t gmem_uvas_map_pages(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, vm_page_t first_page);
gmem_error_t gmem_uvas_map_pages_sg(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, vm_page_t *pages);
gmem_error_t gmem_uvas_unmap(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, void (* unmap_callback(void *)),
	void *callback_args);
gmem_error_t gmem_uvas_protect(gmem_uvas_t *uvas, vm_offset_t start,
	vm_size_t size, vm_prot_t new_protection);


#endif