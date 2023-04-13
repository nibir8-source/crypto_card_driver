#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include <asm/tlbflush.h>
#include <linux/uaccess.h>
#include <linux/device.h>

#include "cryptocard_mod.h"

#define MY_DRIVER "cryptocard_pci_driver"
#define DEVNAME "chardev"
#define KEY_A_OFFSET 0x0a
#define KEY_B_OFFSET 0x0b
#define MMIO_STATUS 0x20
#define MMIO_MSG_LEN 0x0c
#define MMIO_DATA_ADDR 0x80
#define CRYPTOCARD_VENDOR_ID 0x1234
#define CRYPTOCARD_DEVICE_ID 0xDEBA

typedef void* ADDR_PTR;
typedef int DEV_HANDLE;
typedef unsigned char KEY_COMP;


static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

struct key_struct{
  KEY_COMP a;
  KEY_COMP b;
};

struct data_struct{
  ADDR_PTR addr;
  uint64_t length;
  uint8_t isMapped;
};

/* This is a "private" data structure */
/* You can store there any data that should be passed between driver's functions */
struct my_driver_priv {
    u32 __iomem *hwmem;
};


static int demo_open(struct inode *inode, struct file *file)
{
        atomic_inc(&device_opened);
        try_module_get(THIS_MODULE);
        printk(KERN_INFO "Device opened successfully\n");
        return 0;
}

static int demo_release(struct inode *inode, struct file *file)
{
        atomic_dec(&device_opened);
        module_put(THIS_MODULE);
        printk(KERN_INFO "Device closed successfully\n");
        return 0;
}

static ssize_t device_read(struct file *filp,
                           char *buffer,
                           size_t length,
                           loff_t * offset){
    printk("read called\n");
    return 0;
}

static ssize_t
device_write(struct file *filp, const char *buff, size_t len, loff_t * off){
    
    printk("write called\n");
    return 8;
}

static int print_data(void * addr, int length){
    char *buff = NULL;
    buff = (char *)vmalloc(length);
    if(copy_from_user(buff, addr,length)){
        pr_err("Copying key data from encryption from user failed\n");
        return -1;
    }
    printk("Data content: %s\n", buff);
    vfree(buff);
    return 0;
}

long device_ioctl(struct file *file,	
		 unsigned int ioctl_num,
		 unsigned long ioctl_param)
{
	//unsigned long addr = 1234;
	int ret = 0; // on failure return -1
	struct key_struct *k_buff = NULL;
    struct data_struct *d_buff = NULL;
    KEY_COMP a, b;
    ADDR_PTR addr;
    uint64_t length;
    uint8_t isMapped;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct my_driver_priv *drv_priv = (struct my_driver_priv *) pci_get_drvdata(pdev);
    printk("PCI dev: %p, Data: %p\n", pdev, drv_priv);

	/*
	 * Switch according to the ioctl called
	 */
	switch (ioctl_num) {
        case IOCTL_SET_KEY:
            printk("Set key a and b\n");
            k_buff = (struct key_struct*)vmalloc(sizeof(struct key_struct)) ;
            if(copy_from_user(k_buff,(char*)ioctl_param,sizeof(struct key_struct))){
                pr_err("Copying key a and b from user failed\n");
                return ret;
            }
            a = k_buff->a;
            b = k_buff->b;
            // writel(a, drv_priv->hwmem + KEY_A_OFFSET);
            // writel(b, drv_priv->hwmem + KEY_B_OFFSET);
            printk("Ptr: %p\n", drv_priv->hwmem);
            *(drv_priv->hwmem + KEY_A_OFFSET) = a;
            *(drv_priv->hwmem + KEY_B_OFFSET) = b;
            printk("Key writing finshed with values %d, %d\n", *(drv_priv->hwmem + KEY_A_OFFSET), *(drv_priv->hwmem + KEY_B_OFFSET));
            vfree(k_buff);
            return ret;
        case IOCTL_ENCRYPT:
            printk("Start encryption\n");
            d_buff = (struct data_struct*)vmalloc(sizeof(struct data_struct)) ;
            if(copy_from_user(d_buff,(char*)ioctl_param,sizeof(struct data_struct))){
                pr_err("Copying key data from encryption from user failed\n");
                return -1;
            }
            addr = d_buff->addr;
            length = d_buff->length;
            isMapped = d_buff->isMapped;
            // *(drv_priv->hwmem + MMIO_MSG_LEN) = length;
            // *(drv_priv->hwmem + MMIO_STATUS) = 0x00;
            writel(length, drv_priv->hwmem + MMIO_MSG_LEN);
            writel(0x00, drv_priv->hwmem + MMIO_STATUS);
            writel((unsigned long)addr, drv_priv->hwmem + MMIO_DATA_ADDR);
            // *(drv_priv->hwmem + MMIO_DATA_ADDR) = (unsigned long)addr;
            printk("Status reg content: %x\n", readl(drv_priv->hwmem + MMIO_STATUS));
            while(readl(drv_priv->hwmem + MMIO_STATUS) == 0x1);
            printk("End encryption");
            print_data(addr, length);
            vfree(d_buff);
            return ret;
        case IOCTL_DECRYPT:
            printk("Start decryption\n");
            d_buff = (struct data_struct*)vmalloc(sizeof(struct data_struct)) ;
            if(copy_from_user(d_buff,(char*)ioctl_param,sizeof(struct data_struct))){
                pr_err("Copying key data from decryption from user failed\n");
                return -1;
            }
            addr = d_buff->addr;
            length = d_buff->length;
            isMapped = d_buff->isMapped;
            writel(length, drv_priv->hwmem + MMIO_MSG_LEN);
            writel(0x02, drv_priv->hwmem + MMIO_STATUS);
            writel((unsigned long)addr, drv_priv->hwmem + MMIO_DATA_ADDR);
            // *(drv_priv->hwmem + MMIO_DATA_ADDR) = (unsigned long)addr;
            printk("Status reg content: %x\n", readl(drv_priv->hwmem + MMIO_STATUS));
            while(readl(drv_priv->hwmem + MMIO_STATUS) == 0x3);
            printk("End decryption");
            vfree(d_buff);
            return ret;
	}
	return ret;
}

static struct file_operations fops = {
        .read = device_read,
        .write = device_write,
        .unlocked_ioctl = device_ioctl,
        .open = demo_open,
        .release = demo_release,
};

static char *demo_devnode(struct device *dev, umode_t *mode)
{
        if (mode && dev->devt == MKDEV(major, 0))
                *mode = 0666;
        return NULL;
}

/* This driver supports device with VID = 0x1234, and PID = 0xDEBA*/
static struct pci_device_id my_driver_id_table[] = {
    { PCI_DEVICE(0x1234, 0xDEBA) },
    {0,}
};

MODULE_DEVICE_TABLE(pci, my_driver_id_table);

static int my_driver_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void my_driver_remove(struct pci_dev *pdev);

/* Driver registration structure */
static struct pci_driver my_driver = {
    .name = MY_DRIVER,
    .id_table = my_driver_id_table,
    .probe = my_driver_probe,
    .remove = my_driver_remove
};


static int __init mypci_driver_init(void)
{
    /* Register new PCI driver */
    int err;
	printk(KERN_INFO "Hello kernel\n");
            
    major = register_chrdev(0, DEVNAME, &fops);
    err = major;
    if (err < 0) {      
            printk(KERN_ALERT "Registering char device failed with %d\n", major);   
            goto error_regdev;
    }                 
    
    demo_class = class_create(THIS_MODULE, DEVNAME);
    err = PTR_ERR(demo_class);
    if (IS_ERR(demo_class))
            goto error_class;

    demo_class->devnode = demo_devnode;

    demo_device = device_create(demo_class, NULL,
                                    MKDEV(major, 0),
                                    NULL, DEVNAME);
    err = PTR_ERR(demo_device);
    if (IS_ERR(demo_device))
            goto error_device;

    printk(KERN_INFO "I was assigned major number %d. To talk to\n", major);                                                              
    atomic_set(&device_opened, 0);

    return pci_register_driver(&my_driver);

error_device:
    class_destroy(demo_class);
error_class:
    unregister_chrdev(major, DEVNAME);
error_regdev:
    return  err;
}

static void __exit mypci_driver_exit(void)
{
    /* Unregister */
    device_destroy(demo_class, MKDEV(major, 0));
    class_destroy(demo_class);
    unregister_chrdev(major, DEVNAME);
    pci_unregister_driver(&my_driver);
	printk(KERN_INFO "Goodbye kernel\n");
}

void release_device(struct pci_dev *pdev)
{
    /* Free memory region */
    pci_release_region(pdev, pci_select_bars(pdev, IORESOURCE_MEM));
    /* And disable device */
    pci_disable_device(pdev);
}

/* This function is called by the kernel */
static int my_driver_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    int bar, err;
    u16 vendor, device;
    unsigned long mmio_start,mmio_len;
    struct my_driver_priv *drv_priv;

    /* Let's read data from the PCI device configuration registers */
    pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
    pci_read_config_word(pdev, PCI_DEVICE_ID, &device);

    printk(KERN_INFO "Device vid: 0x%X pid: 0x%X\n", vendor, device);

    /* Request IO BAR */
    bar = pci_select_bars(pdev, IORESOURCE_MEM);

    /* Enable device memory */
    err = pci_enable_device_mem(pdev);

    if (err) {
        return err;
    }

    /* Request memory region for the BAR */
    err = pci_request_region(pdev, bar, MY_DRIVER);

    if (err) {
        pci_disable_device(pdev);
        return err;
    }

    /* Get start and stop memory offsets */
    mmio_start = pci_resource_start(pdev, 0);
    mmio_len = pci_resource_len(pdev, 0);

    /* Allocate memory for the driver private data */
    drv_priv = kzalloc(sizeof(struct my_driver_priv), GFP_KERNEL);

    if (!drv_priv) {
        release_device(pdev);
        return -ENOMEM;
    }

    /* Remap BAR to the local pointer */
    drv_priv->hwmem = ioremap(mmio_start, mmio_len);
    printk(KERN_INFO "Device Memory ID: 0x%X Addr: %p\n", *(drv_priv->hwmem), drv_priv->hwmem);

    if (!drv_priv->hwmem) {
       release_device(pdev);
       return -EIO;
    }

    /* Set driver private data */
    /* Now we can access mapped "hwmem" from the any driver's function */
    pci_set_drvdata(pdev, drv_priv);

    // write_sample_data(pdev);

    return 0;
}

static void my_driver_remove(struct pci_dev *pdev)
{
    struct my_driver_priv *drv_priv = pci_get_drvdata(pdev);

    if (drv_priv) {
        if (drv_priv->hwmem) {
            iounmap(drv_priv->hwmem);
        }

        kfree(drv_priv);
    }

    release_device(pdev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nibir Baruah <contact@nibir@iitk.ac.in>");
MODULE_DESCRIPTION("Test PCI driver");
MODULE_VERSION("0.1");

module_init(mypci_driver_init);
module_exit(mypci_driver_exit);