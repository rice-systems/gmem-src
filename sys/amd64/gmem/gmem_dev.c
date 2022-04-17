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
#include <sys/param.h>
#include <sys/domainset.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <sys/selinfo.h>
#include <sys/smp.h>
#include <sys/pipe.h>
#include <sys/bio.h>
#include <sys/buf.h>
#include <sys/bus.h>
#include <sys/vmem.h>
#include <sys/vmmeter.h>
#include <sys/tree.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>

#include <sys/gmem.h>
#include <amd64/gmem/gmem_dev.h>
#include <amd64/gmem/gmem_uvas.h>

static gmem_devmap_t gmem_devmap_store;
#define gmem_devmap (&gmem_devmap_store)

static SYSCTL_NODE(_vm, OID_AUTO, gmem, CTLFLAG_RD, 0, "GMEM Info");

static int gmem_inited = 0;
SYSCTL_INT(_vm_gmem, OID_AUTO, gmem_init, CTLFLAG_RD,
    &gmem_inited, 0,
    "Whether gmem is initialized");

static void gmem_dev_init(void);
SYSINIT(gmem_dev_init, SI_SUB_DRIVERS - 1, SI_ORDER_FIRST, gmem_dev_init, NULL);

static void gmem_dev_init(void)
{
	int i;

	mtx_init(&gmem_devmap->lock, "global gmem device map", NULL, MTX_DEF);
	gmem_devmap->unr = new_unrhdr(0, MAXNGMEMDEV - 1, NULL);
	for (i = 0; i < MAXNGMEMDEV; i ++)
		gmem_devmap->dev[i] = NULL;

	gmem_inited = 1;
	printf("GMEM DEV INIT PASS\n");
}

// allocate a device in gmem_devmap
static gmem_dev_t* gmem_devmap_alloc_dev()
{
	uint16_t dev_id;

	GMEM_DEVMAP_ASSERT_LOCKED(gmem_devmap);

	dev_id = alloc_unr(gmem_devmap->unr);
	if (dev_id + 1 == 0)
		panic("gmem dev id allocation failed");

	gmem_devmap->dev[dev_id] = malloc(sizeof(gmem_dev_t), M_DEVBUF, M_WAITOK);
	if (gmem_devmap->dev[dev_id] == NULL)
		panic("ENOMEM allocating new gmem dev struct");
	gmem_devmap->dev[dev_id]->id = dev_id;

	return gmem_devmap->dev[dev_id];
}

// free a device in gmem_devmap
static void gmem_devmap_free_dev(gmem_dev_t *gmem_dev)
{
	uint16_t dev_id;

	GMEM_DEVMAP_ASSERT_LOCKED(gmem_devmap);

	// recycle dev_id
	dev_id = gmem_dev->id;
	free_unr(gmem_devmap->unr, dev_id);

	// clear references
	device_set_gmem_dev(gmem_dev->device, NULL);
	gmem_devmap->dev[dev_id] = NULL;

	free(gmem_dev, M_DEVBUF);
}

static gmem_dev_t * gmem_devmap_lookup_id(uint16_t dev_id)
{
	GMEM_DEVMAP_ASSERT_LOCKED(gmem_devmap);

	return gmem_devmap->dev[dev_id];
}

gmem_dev_t * gmem_dev_add(device_t device, gmem_mmu_ops_t *mmu_ops)
{
	gmem_dev_t* dev;

	dev = device_get_gmem_dev(device);
	if (dev != NULL && dev == gmem_devmap_lookup_id(dev->id))
	{
		// TODO: add a new sysctl int to count redundantly added devices
		printf("REDUNDANT GMEM DEV ADD DETECTED");
		return dev;
	}

	GMEM_DEVMAP_LOCK(gmem_devmap);
	dev = gmem_devmap_alloc_dev();
	device_set_gmem_dev(device, dev);
	dev->device = device;
	dev->cur_pmap = NULL;
	dev->mmu_ops = mmu_ops;
	GMEM_DEVMAP_UNLOCK(gmem_devmap);

	mmu_ops->mmu_init(mmu_ops);

	return dev;
}

void gmem_dev_remove(gmem_dev_t *dev)
{
	GMEM_DEVMAP_LOCK(gmem_devmap);
	gmem_devmap_free_dev(dev);
	GMEM_DEVMAP_UNLOCK(gmem_devmap);
}

bool is_gmem_dev(device_t device)
{
	return (device_get_gmem_dev(device) != NULL);
}