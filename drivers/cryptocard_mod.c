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
#include <linux/io.h>
#include <linux/semaphore.h>
#include <linux/dma-mapping.h>

#include "cryptocard_mod.h"

#define MY_DRIVER "cryptocard_pci_driver"
#define DEVNAME "chardev"
#define KEY_A_OFFSET 10
#define KEY_B_OFFSET 11
#define MMIO_STATUS 32
#define MMIO_MSG_LEN 12
#define MMIO_DATA_ADDR 128
#define MMIO_UNUSED_OFFSET 168
#define OFF 8
#define ISR_OFFSET 36
#define ACK_OFFSET 100
#define DMA_BUFFER_SIZE PAGE_SIZE
#define DMA_DATA_ADDR 144
#define DMA_MSG_LEN 152
#define DMA_STATUS 160

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
  int is_encrypt;
};

struct config_struct{
  config_t type;
  uint8_t value;
};

/* This is a "private" data structure */
/* You can store there any data that should be passed between driver's functions */
struct my_driver_priv {
    void __iomem *hwmem;
    int is_interrupt;
    int is_dma;
    struct semaphore sem;
    void *dma_buffer;
    size_t buffer_size;
    dma_addr_t dma_handle;
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

// static int print_data(void * addr, int length){
//     char *buff = NULL;
//     buff = (char *)vmalloc(length);
//     if(copy_from_user(buff, addr,length)){
//         pr_err("Copying key data from encryption from user failed\n");
//         return -1;
//     }
//     printk("Data content: %s\n", buff);
//     vfree(buff);
//     return 0;
// }

static int do_mmio_enc_dec(struct data_struct *d_buff, ADDR_PTR addr, uint64_t length){
    int flag;
    char *buff = NULL;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct my_driver_priv *drv_priv = (struct my_driver_priv *) pci_get_drvdata(pdev);
    printk("Start MMIO\n");
    buff = (char *)vmalloc(length);
    if(copy_from_user(buff,(char *)addr,length)){
        pr_err("Copying data from cryption from user failed\n");
        return -1;
    }
    writel(length, drv_priv->hwmem + MMIO_MSG_LEN);
    writel((drv_priv->is_interrupt? 128 : 0) | (d_buff->is_encrypt ? 0 : 2), drv_priv->hwmem + MMIO_STATUS);
    for(int i = 0; i<length; i++){
        writeb(buff[length-1-i], drv_priv->hwmem + MMIO_UNUSED_OFFSET + i);
    }
    writeq(MMIO_UNUSED_OFFSET, drv_priv->hwmem + MMIO_DATA_ADDR);
    if(drv_priv->is_interrupt){
        if(down_interruptible(&drv_priv->sem)){
            return -ERESTARTSYS;
        }
    }else {
        flag = 1 | (d_buff->is_encrypt ? 0 : 2);
        while(readl(drv_priv->hwmem + MMIO_STATUS) == flag);
    }
    for(int i = 0; i<length; i++){
        buff[length-1-i] = readb(drv_priv->hwmem + MMIO_UNUSED_OFFSET + i);
    }
    if(copy_to_user(addr, buff,length)){
        pr_err("Copying data from cryption to user failed\n");
        return -1;
    }
    printk("End MMIO\n");
    return 0;
}

static int do_dma_enc_dec(struct data_struct *d_buff, ADDR_PTR addr, uint64_t length){
    int flag, counter=0;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct my_driver_priv *drv_priv = (struct my_driver_priv *) pci_get_drvdata(pdev);
    printk("Start DMA\n");
    if(copy_from_user(drv_priv->dma_buffer,(char *)addr,length)){
        pr_err("Copying data from cryption from user failed\n");
        return -1;
    }
    writeq(length, drv_priv->hwmem + DMA_MSG_LEN);
    writeq(drv_priv->dma_handle, drv_priv->hwmem + DMA_DATA_ADDR);
    writeq((drv_priv->is_interrupt? 5 : 1) | (d_buff->is_encrypt ? 1 : 3), drv_priv->hwmem + DMA_STATUS);
    if(drv_priv->is_interrupt){
        if(down_interruptible(&drv_priv->sem)){
            return -ERESTARTSYS;
        }
    }else {
        flag = 1 | (d_buff->is_encrypt ? 0 : 2);
        printk("DMA status: %llx", readq(drv_priv->hwmem + DMA_STATUS));
        while(readq(drv_priv->hwmem + DMA_STATUS) == flag){
            counter++;
        };
        printk("DMA loop counter: %d\n", counter);
    }
    if(copy_to_user(addr, drv_priv->dma_buffer,length)){
        pr_err("Copying data from cryption to user failed\n");
        return -1;
    }
    printk("End DMA\n");
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
    struct config_struct *cfg_buff = NULL;
    KEY_COMP a, b;
    ADDR_PTR addr;
    uint64_t length;
    uint8_t isMapped;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct my_driver_priv *drv_priv = (struct my_driver_priv *) pci_get_drvdata(pdev);
    config_t type;
    uint8_t value;
    // unsigned long long bt, ct, dt;
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
            writel((a<<8) | b, drv_priv->hwmem + OFF);
            // writeb(30, drv_priv->hwmem + KEY_A_OFFSET);
            // writeb(17, drv_priv->hwmem + KEY_B_OFFSET);
            vfree(k_buff);
            printk("Key writing finshed\n");
            return ret;
        case IOCTL_ENC_DEC:
            printk("Start cryption\n");
            d_buff = (struct data_struct*)vmalloc(sizeof(struct data_struct)) ;
            if(copy_from_user(d_buff,(char*)ioctl_param,sizeof(struct data_struct))){
                pr_err("Copying key data from encryption from user failed\n");
                return -1;
            }
            addr = d_buff->addr;
            length = d_buff->length;
            isMapped = d_buff->isMapped;
            if(drv_priv->is_dma){
                if(do_dma_enc_dec(d_buff, addr, length)){
                    pr_err("DMA encryption decryption failed\n");
                    vfree(d_buff);
                    return -1;
                }
            }else{
                if(do_mmio_enc_dec(d_buff, addr, length)){
                    pr_err("MMIO encryption decryption failed\n");
                    vfree(d_buff);
                    return -1;
                }
            }
            printk("End cryption");
            // print_data(addr, length);
            vfree(d_buff);
            return ret;
        case IOCTL_SET_CONFIG:
            printk("Start config\n");
            cfg_buff = (struct config_struct*)vmalloc(sizeof(struct config_struct)) ;
            if(copy_from_user(cfg_buff,(char*)ioctl_param,sizeof(struct config_struct))){
                pr_err("Copying key data from encryption from user failed\n");
                return -1;
            }
            type = cfg_buff->type;
            value = cfg_buff->value;
            if(type == INTERRUPT){
                drv_priv->is_interrupt = value;
            }else{
                drv_priv->is_dma = value;
            }
            printk("End config\n");
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

static irqreturn_t my_interrupt_handler(int irq, void * dev_id){
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct my_driver_priv *drv_priv = (struct my_driver_priv *) pci_get_drvdata(pdev);
    u32 isr;
    printk("In interrupt handler\n");

    isr = readl(drv_priv->hwmem + ISR_OFFSET);
    writel(isr, drv_priv->hwmem + ACK_OFFSET);
    up(&drv_priv->sem);
    return IRQ_HANDLED;
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
    sema_init(&drv_priv->sem, 0);

    /* Remap BAR to the local pointer */
    // drv_priv->buffer_size = DMA_BUFFER_SIZE;
    // drv_priv->dma_buffer = dma_alloc_coherent(&pdev->dev, drv_priv->buffer_size, dma_handle, GFP_KERNEL | GFP_ATOMIC);
    drv_priv->is_interrupt = 0;
    drv_priv->is_dma = 0;
    drv_priv->hwmem = ioremap(mmio_start, mmio_len);
    printk("Pointer base %lu\n", (unsigned long)drv_priv->hwmem);

    if (!drv_priv->hwmem) {
       release_device(pdev);
       return -EIO;
    }

    err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
    if(err){
        dev_err(&pdev->dev, "Failed to set DMA mask for device\n");
        goto error;
    }

    drv_priv->dma_buffer = dma_alloc_coherent(&pdev->dev, DMA_BUFFER_SIZE, &drv_priv->dma_handle, GFP_KERNEL);
    if(!drv_priv->dma_buffer){
        dev_err(&pdev->dev, "Failed to allocate DMA buffer\n");
        err = -ENOMEM;
        goto error;
    }

    printk("DMA buffer: %p, DMA Handle: %llx\n", drv_priv->dma_buffer, drv_priv->dma_handle);

    err = request_irq(pdev->irq, my_interrupt_handler, IRQF_SHARED, "my_pci_device", pdev);
    if(err){
        iounmap(drv_priv->hwmem);
        pci_disable_device(pdev);
        goto error;
    }



    /* Set driver private data */
    /* Now we can access mapped "hwmem" from the any driver's function */
    pci_set_drvdata(pdev, drv_priv);

    // write_sample_data(pdev);

    return 0;
error:
    if(drv_priv->dma_buffer){
        dma_free_coherent(&pdev->dev, DMA_BUFFER_SIZE, drv_priv->dma_buffer, drv_priv->dma_handle);
    }
    return err;
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


    free_irq(pdev->irq, pdev);

    release_device(pdev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nibir Baruah <contact@nibir@iitk.ac.in>");
MODULE_DESCRIPTION("Test PCI driver");
MODULE_VERSION("0.1");

module_init(mypci_driver_init);
module_exit(mypci_driver_exit);