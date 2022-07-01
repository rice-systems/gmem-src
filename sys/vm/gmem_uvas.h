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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/vmem.h>
#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

// debugging switch
// #define PRINTINFO  { printf("[%s] %s line #%d\n", __FILE__, __func__, __LINE__); }
#define PRINTINFO  { }
// #define debug_printf(...) { printf(...); }
#ifndef debug_printf
#define debug_printf(...) { }
#endif

#include <machine/atomic.h>
#include <sys/systm.h>
extern int instrument;
#define UVAS_INST_MAP           0
#define UVAS_INST_UNMAP         1 
#define UVAS_INST_VA_ALLOC      2
#define UVAS_INST_VA_FREE       3
#define UVAS_INST_TLB_INV       4
#define UVAS_INST__MAP          5
#define UVAS_INST__UNMAP        6
#define UVAS_INST_STAT_COUNT    7
#define UVAS_INST_MAXPGCNT      512

// indexed by buffer size / 4KB
// 0: buffer size >= 2MB
struct hist
{
	uint64_t latency[UVAS_INST_STAT_COUNT];
	uint64_t count[UVAS_INST_STAT_COUNT];
};

extern struct hist instrument_hist[UVAS_INST_MAXPGCNT];

#define START_STATS \
	uint64_t delta; \
	if (instrument) delta = rdtscp();  \

#define RESET_STATS \
	if (instrument) delta = rdtscp(); \

#define FINISH_STATS(typeId,pgcnt)                              \
	if (instrument) {											\
		delta = rdtscp() - delta;                                         \
		if (pgcnt < UVAS_INST_MAXPGCNT && typeId < UVAS_INST_STAT_COUNT) { \
			atomic_add_64(&(instrument_hist[pgcnt].latency[typeId]), delta);  \
			atomic_add_64(&(instrument_hist[pgcnt].count[typeId]), 1);        \
		} \
	} \

#define UVAS_ENQUEUE_LOCK(x)    mtx_lock(&(x)->enqueue_lock)
#define UVAS_ENQUEUE_UNLOCK(x)  mtx_unlock(&(x)->enqueue_lock)
#define UVAS_ENQUEUE_TRYLOCK(x) mtx_trylock(&(x)->enqueue_lock)
#define UVAS_ASSERT_ENQUEUE_LOCKED(x) mtx_assert(&(x)->enqueue_lock, MA_OWNED)

#define UVAS_DEQUEUE_LOCK(x)    mtx_lock(&(x)->dequeue_lock)
#define UVAS_DEQUEUE_UNLOCK(x)  mtx_unlock(&(x)->dequeue_lock)
#define UVAS_DEQUEUE_TRYLOCK(x) mtx_trylock(&(x)->dequeue_lock)
#define UVAS_ASSERT_DEQUEUE_LOCKED(x) mtx_assert(&(x)->dequeue_lock, MA_OWNED)

#define GMEM_UVAS_LOCK(x) mtx_lock(&(x)->lock)
#define GMEM_UVAS_UNLOCK(x) mtx_unlock(&(x)->lock)
#define GMEM_UVAS_ASSERT_LOCKED(x) mtx_assert(&(x)->lock, MA_OWNED)

// #define	IOMMU_PGF_WAITOK	0x0001
#define GMEM_WAITOK		0x0001

/* Map flags */
#define	GMEM_MF_CANWAIT		0x0001
#define	GMEM_MF_CANSPLIT	0x0002
#define	GMEM_MF_RMRR		0x0004
#define GMEM_UVA_ALLOC            0x0000
#define GMEM_UVA_ALLOC_FIXED      0x0008

/* UVAS MODE */
#define GMEM_UVAS_UNIQUE     0x0
#define GMEM_UVAS_SHARE_CPU  0x1
#define GMEM_UVAS_REPLICATED 0x2
#define GMEM_UVAS_EXCLUSIVE  0x3
#define GMEM_UVAS_REPLICATE_CPU  0x4
#define GMEM_UVAS_SHARE  0x5



#define	GMEM_UVAS_ENTRY_PLACE	0x0001	/* Fake entry */
#define	GMEM_UVAS_VMEM_XALLOC	0x0002
#define	GMEM_UVAS_ENTRY_TRACKED	0x0004
#define	GMEM_UVAS_ENTRY_UNMAPPED	0x0010	/* No backing pages */
#define	GMEM_UVAS_ENTRY_QI_NF	0x0020	/* qi task, do not free entry */
#define	GMEM_UVAS_ENTRY_READ	0x1000	/* Read permitted */
#define	GMEM_UVAS_ENTRY_WRITE	0x2000	/* Write permitted */
#define	GMEM_UVAS_ENTRY_SNOOP	0x4000	/* Snoop */
#define	GMEM_UVAS_ENTRY_TM	0x8000	/* Transient */
#define GMEM_PROT_READ 		0x0001
#define GMEM_PROT_WRITE     0x0002
#define GMEM_PAGE_SIZE 4096
#define GMEM_PAGE_SHIFT 12
#define GMEM_PAGE_MASK (GMEM_PAGE_SIZE - 1)

static inline bool
gmem_test_boundary(vm_offset_t start, vm_offset_t size, vm_offset_t boundary)
{

	if (boundary == 0)
		return (true);
	return (start + size <= ((start + boundary) & ~(boundary - 1)));
}

#include <sys/tree.h>
RB_HEAD(gmem_uvas_entries_tree, gmem_uvas_entry);
RB_PROTOTYPE(gmem_uvas_entries_tree, gmem_uvas_entry, rb_entry,
    gmem_uvas_cmp_entries);

enum gmem_uvas_allocator_type {
	RBTREE = 0,
	VMEM,
	CPU_VM
};

// Canonical address space: 0~maxsize
struct gmem_vma_format
{
	// vm_offset_t low_addr;
	// vm_offset_t high_addr;
	vm_offset_t alignment;
	vm_offset_t boundary;
	vm_offset_t maxaddr;
	vm_offset_t guard;
};

TAILQ_HEAD(gmem_uvas_entries_tailq, gmem_uvas_entry);
TAILQ_HEAD(unmap_task_tailq, unmap_request);

struct gmem_uvas // VM counterpart: struct vm_map
{
	struct mtx lock, enqueue_lock, dequeue_lock;

	// List of mapped entries
	struct gmem_uvas_entries_tailq mapped_entries;

	// Whether this uvas needs lookup of its entries
	// This determines whether it uses vmem or rb-tree to allocate/free uvas entries.
	enum gmem_uvas_allocator_type allocator;

	// uva arena for va allocation
	// We have to use a rb tree entry to support split/merge/lookup
	// but we may use vmem as well to allocate va span quickly
	vmem_t *arena;

	struct gmem_uvas_entries_tree rb_root;
	struct gmem_uvas_entry *first_place, *last_place;

	// Number of entires
	uint32_t entries_cnt;

	// format of uvas
	struct gmem_vma_format format;

	// max va
	// vm_size_t end;

	// A uvas may be used by multiple pmaps (mmus)
	TAILQ_HEAD(dev_pmap_tailq, dev_pmap) dev_pmap_header;

	// producer queue
	struct unmap_task_tailq unmap_requests;
	uint32_t unmap_pages;

	// consumer queue
	struct unmap_task_tailq unmap_workspace;
	uint32_t unmap_working_pages;

	int async_unmap_proc;
};

// IOMMU:
// the iommu_map_entry used to have a dmamap_link field
// used to serve for queued invalidations as an iommu-specific 
// data structure. 
// We decouple this from the map_entry and create a new data
// structure for intel_qi.c to utilize. This means that there
// is a tax of decoupling data structure. We need to track this
// type of cost.
// 
// The gmem_uvas_entry can also be used as a data sturcutre to pass
// the specified va_span. Do not waste other data structures.
// 
// The definition of uvas entry fits rb-tree allocator
// Without lookup requirement, they are not necessary.
// split and merge may be applied if protection or vm_ops change
struct gmem_uvas_entry // VM counterpart: struct vm_map_entry
{
	vm_offset_t start;
	vm_offset_t end;
	vm_offset_t first;
	vm_offset_t last;
	vm_size_t free_down;

	// We do not have physical management, skip them
	// vm_object_t object;	/* the vm object this entry point to */
	// vm_ooffset_t offset;		/* offset into object */

	// a doubly linked list of entries sorted by base
	TAILQ_ENTRY(gmem_uvas_entry) mapped_entry;

	// rb-tree entry for query/delete/insert
	RB_ENTRY(gmem_uvas_entry) rb_entry;

	// changes of protection or pmap may result in splitting or merging
	vm_prot_t protection;

	// entry flags
	u_int flags;

	// The unified address space it points to
	gmem_uvas_t *uvas;
};

#define GMEM_MMU_LOCK(ops) mtx_lock(&ops->lock)
#define GMEM_MMU_UNLOCK(ops) mtx_unlock(&ops->lock)

struct gmem_mmu_ops
{
	// immutable variables once set
	// bitmap of available page shifts for page-based TLB
	unsigned long pgsize_bitmap;
	bool mmu_has_range_tlb;
	int inited;
	vm_paddr_t pa_min, pa_max;

	// init function that initializes this mmu ops, including a global queue for tlb inv
	gmem_error_t (*mmu_init)(struct gmem_mmu_ops *);

	// device zeroing or just no-op 
	gmem_error_t (*prepare)(vm_paddr_t pa, vm_size_t size);

	// device page/range table creation and destruction.
	gmem_error_t (*mmu_pmap_create)(dev_pmap_t *pmap);
	gmem_error_t (*mmu_pmap_destroy)(dev_pmap_t *pmap);

	// device mapping creation, manipulation and destruction
	// We do not include batching mechanism here, as we will not exercise
	// any throughput devices at this moment
	// We also do not include async version for map, as it will not be used
	gmem_error_t (*mmu_pmap_enter)(dev_pmap_t *pmap, vm_offset_t va, vm_size_t size, 
		vm_paddr_t pa, u_int prot, u_int mem_flags);
	gmem_error_t (*mmu_pmap_release)(dev_pmap_t *pmap, vm_offset_t va, vm_size_t size);
	gmem_error_t (*mmu_pmap_protect)(vm_offset_t va, vm_size_t size, vm_prot_t new_prot);
	void (*mmu_tlb_invl)(dev_pmap_t *pmap, vm_offset_t va, vm_size_t size);
	gmem_error_t (*mmu_tlb_flush)(struct gmem_uvas_entries_tailq *entries);
	gmem_error_t (*mmu_pmap_kill)(dev_pmap_t *pmap, struct gmem_uvas_entries_tailq *ext_entries);
	void (*mmu_tlb_invl_coalesced)(dev_pmap_t *pmap);

	// hacks for simulating exclusive mode
	// real device should have vm_page struct registered at boot time and let CPU VM manage them.
	vm_page_t (*alloc_page) (dev_pmap_t *pmap);
	void (*zero_page)(vm_page_t m);
	gmem_error_t (*free_page) (vm_page_t m);
	vm_page_t (*get_victim_page) (void);
};

// A collection of pmaps that are registed in replication mode for a uvas
// devices of the pmap must come from the same NUMA group
// Well, at this moment all pmap come from a single NUMA group.
struct dev_pmap_replica
{
	uint8_t npmaps;
	struct dev_pmap **replicated_pmaps;
};

struct unmap_request
{
	gmem_uvas_entry_t *entry;
	void (* cb)(void *args);
	void *cb_args;
	TAILQ_ENTRY(unmap_request) next;
};

struct dev_pmap_policy {
	bool fault_with_replica; // if you want to support system-level SVM (coordinated faulting)
	bool pin_on_fault; // if you want eager preparation or don't support device page fault
	uint8_t prepare_page_order; // (1 << #) of pages to prepare (zeroing, migration etc) at dev fault time
};

enum gmem_vm_mode {
	UNIQUE = 0,
	REPLICATE,
	SHARE,
	REPLICATE_CPU,
	SHARE_CPU,
	EXCLUSIVE,
};
typedef enum gmem_vm_mode gmem_vm_mode;

// device-dependent mapping data
// A pmap is coupled with an mmu instance
struct dev_pmap
{
	gmem_vm_mode mode;

	// An array of the mapping devices
	uint8_t ndevices;

	struct dev_pmap_policy policy;

	// for convenience, use a tailq for devices sharing this dev_pmap
	TAILQ_HEAD(gmem_dev_tailq, gmem_dev) gmem_dev_header;

	dev_pmap_t *replica_of_cpu; // Let CPU replicate it
	struct dev_pmap_replica *pmap_replica;

	// A pointer to its unified address space
	struct gmem_uvas *uvas;

	// list of pmaps included by a uvas
	// Some pmaps may have exclusive mappings, some pmaps may have replicated mappings
	// We might need a list of exclusive mappings in the future when supporting 
	// physical memory management
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

	// minimum sp shift (dev-specific)
	uint8_t min_sp_shift;
};

void gmem_uvas_set_pmap_policy(dev_pmap_t *pmap, bool fault_with_replica, bool pin_on_fault, uint8_t prepare_page_order);
struct gmem_uvas_entry* gmem_uvas_alloc_entry(struct gmem_uvas *uvas, u_int flags);
void gmem_uvas_free_entry(struct gmem_uvas *uvas, struct gmem_uvas_entry *entry);
gmem_error_t gmem_uvas_create(gmem_uvas_t **uvas_res, dev_pmap_t **pmap_res, gmem_dev_t *dev, gmem_mmu_ops_t *mmu_ops,
	dev_pmap_t *pmap_to_share, void *dev_data, int mode,
	vm_offset_t alignment, vm_offset_t boundary, vm_offset_t size, vm_offset_t guard);
gmem_error_t gmem_uvas_delete(gmem_uvas_t *uvas);
gmem_error_t gmem_uvas_map_pages(dev_pmap_t *pmap, vm_offset_t start,
	vm_size_t size, vm_page_t first_page, u_int prot, u_int mem_flags);
// gmem_error_t gmem_uvas_prepare_and_map_pages_sg(dev_pmap_t *pmap, vm_offset_t start,
// 	vm_size_t size, vm_page_t *pages, u_int prot, u_int mem_flags);
gmem_error_t gmem_uvas_unmap(dev_pmap_t *pmap, gmem_uvas_entry_t *entry, int wait,
	void (* unmap_callback)(void *),
	void *callback_args);
gmem_error_t gmem_uvas_protect(gmem_uvas_t *uvas, vm_offset_t start,
	vm_size_t size, vm_prot_t new_protection);

// Free the va span defined by [start, start + size) or defined by
// entry, if entry != NULL
gmem_error_t gmem_uvas_free_span(gmem_uvas_t *uvas, gmem_uvas_entry_t *entry);

// Allocate a VA span with a given size, *start returns the offset and *ret returns a
// pointer to the va span
gmem_error_t gmem_uvas_alloc_span(gmem_uvas_t *uvas, 
	vm_offset_t *start, vm_size_t size, vm_prot_t protection, 
	u_int flags, gmem_uvas_entry_t **ret);

// Allocate a VA span with a given start and end. The allocation could fail if overlapping
// with exiting VA span.
gmem_error_t gmem_uvas_alloc_span_fixed(gmem_uvas_t *uvas, 
	vm_offset_t start, vm_offset_t end, vm_prot_t protection, u_int flags, gmem_uvas_entry_t **ret);

// GMEM-based functions for map/unmap
gmem_error_t gmem_mmap_eager(gmem_uvas_t *uvas, dev_pmap_t *pmap, vm_offset_t *start, vm_offset_t size,
	u_int eflags, u_int flags, vm_page_t *ma, bool track, gmem_uvas_entry_t **ret);

// Generic pmap kill function
gmem_error_t gmem_mmu_pmap_kill_generic(dev_pmap_t *pmap, struct gmem_uvas_entries_tailq *ext_entries);

void gmem_uvas_drain_unmap_tasks(gmem_uvas_t *uvas);

gmem_error_t gmem_uvas_unmap_external(gmem_uvas_t *uvas, struct gmem_uvas_entries_tailq *ext_entries, 
	int wait, void (* unmap_callback)(void *), void *callback_args, bool sleepable);
gmem_error_t gmem_uvas_unmap_all(gmem_uvas_t *uvas, int wait,
	void (* unmap_callback)(void *), void *callback_args);
gmem_error_t pmap_reload_mmu(dev_pmap_t *pmap, gmem_mmu_ops_t *new_mmu);

int gmem_uvas_fault(dev_pmap_t *pmap, vm_offset_t addr, vm_offset_t len, vm_prot_t prot, vm_page_t *out);

#endif