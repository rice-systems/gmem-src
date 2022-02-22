/*-
 * 
 * This software was developed by Weixi Zhu <wxzhu@rice.edu>
 * for gmem project.
 *
 * GMEM is a generic memory management interface for CPU and devices
 * It currently only supports x86_64 platforms.
 *
 */

#ifndef _GMEM_DEV_H_
#define	_GMEM_DEV_H_

#define MAXNGMEMDEV 256

// Right now we assume SR-IOV as the only way to partition a device. 
// No context switch should happen for time-based division.
// As a start GMEM only considers unified address space. 
struct gmem_dev
{
	// a pointer to its FreeBSD's struct device
	device_t device;

	// A unique identifier for gmem_dev
	uint16_t id;

	// cached pmap pointer, updated by device context switch
	dev_pmap_t *cur_pmap;

	// Do not consider:
	//   1. hiererchical MMUs for nested translations, as gmem interfaces should run independently
	// To consider:
	//   1. dynamic mmu changes. E.g. device hotplug in guest OS.
	gmem_mmu_ops_t *mmu_ops;

	// list of gmem devs sharing the same pmap
	TAILQ_ENTRY(gmem_dev) gmem_dev_list;
};

// global list (hashmap) of gmem devices 
struct gmem_devmap_info
{
	struct mtx lock;
	struct unrhdr *unr;
	gmem_dev_t* dev[MAXNGMEMDEV];
};

// GMEM KPIs for devices
gmem_dev_t* gmem_dev_add(device_t device, gmem_mmu_ops_t *mmu_ops);
void gmem_dev_remove(gmem_dev_t *dev);
bool is_gmem_dev(device_t device);

#define	GMEM_DEVMAP_ASSERT_LOCKED(devmap)		mtx_assert(&(devmap)->lock, MA_OWNED)
#define	GMEM_DEVMAP_ASSERT_UNLOCKED(devmap)		mtx_assert(&(devmap)->lock, MA_NOTOWNED)

#define	GMEM_DEVMAP_LOCK(devmap)				mtx_lock(&(devmap)->lock)
#define	GMEM_DEVMAP_UNLOCK(devmap)				mtx_unlock(&(devmap)->lock)

#endif