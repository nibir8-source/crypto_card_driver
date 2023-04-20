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
#include <uapi/asm-generic/mman-common.h>

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
#define INIT_INSERT 0
#define KEY_INSERT 1
#define CONFIG_INSERT 2

#define CRYPTOCARD_VENDOR_ID 0x1234
#define CRYPTOCARD_DEVICE_ID 0xDEBA

typedef void* ADDR_PTR;
typedef int DEV_HANDLE;
typedef unsigned char KEY_COMP;

#define MAX_BUCKETS 1000

struct proc_struct{
    KEY_COMP a;
    KEY_COMP b;
    uint8_t is_dma;
    uint8_t is_interrupt;
    uint8_t key_set_flag;
};

struct node{
    int pid;
    struct proc_struct data;
    struct node *next;
};

struct key_pair{
    KEY_COMP a;
    KEY_COMP b;
};

struct config_pair{
    config_t type;
    uint8_t val;
};

struct node *h_ps[MAX_BUCKETS];

static int hash(int pid){
    return pid % (MAX_BUCKETS);
}


static struct node *find(int pid){
    int hid = hash(pid);
    struct node *curr = h_ps[hid];
    while(curr != NULL){
        if(curr->pid == pid){
            return (curr);
        }
        curr = curr->next;
    }
    return NULL;
}


static void insert(int flag, void *arg){
    struct key_pair *kp = NULL;
    struct config_pair *cfgp = NULL;
    struct node *h_node = NULL;
    struct node *curr = NULL;
    int pid = current->pid;
    int hid = hash(pid);
    switch(flag){
        case INIT_INSERT:
            if(h_ps[hid] != NULL){
                curr = h_ps[hid];
            }
            h_ps[hid] = (struct node *)vmalloc(sizeof(struct node));
            h_ps[hid]->pid = pid;
            h_ps[hid]->data.is_dma = h_ps[hid]->data.is_interrupt = h_ps[hid]->data.key_set_flag = 0;   
            h_ps[hid]->next = curr;
            break;
        case KEY_INSERT:
            kp = (struct key_pair *)arg;
            h_node = find(pid);
            h_node->data.a = kp->a;
            h_node->data.b = kp->b;
            h_node->data.key_set_flag = 1;
            break;
        case CONFIG_INSERT:
            cfgp = (struct config_pair *)arg;
            h_node = find(pid);
            if(cfgp->type == INTERRUPT){
                h_node->data.is_interrupt = cfgp->val;
            }else{
                h_node->data.is_dma = cfgp->val;
            }
            break;
    }
    return;
}


static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

struct key_struct{
  KEY_COMP a;
  KEY_COMP b;
  int pid;
};

struct data_struct{
  uint64_t addr;
  uint64_t length;
  uint8_t isMapped;
  int is_encrypt;
};

struct config_struct{
  config_t type;
  uint8_t value;
};

struct map_struct{
  ADDR_PTR addr;
  uint64_t size;
};

struct semaphore lock;

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
    uint64_t size;
};

uint64_t base_addr;

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

static int do_mmio_enc_dec(struct data_struct *d_buff, ADDR_PTR addr, uint64_t length){
    int flag;
    char *buff = NULL;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct my_driver_priv *drv_priv = (struct my_driver_priv *) pci_get_drvdata(pdev);
    struct proc_struct ps = find(current->pid)->data; 
    printk("Start MMIO\n");
    buff = (char *)vmalloc(length);
    if(copy_from_user(buff,(char *)addr,length)){
        pr_err("Copying data from cryption from user failed\n");
        return -1;
    }
    writel(length, drv_priv->hwmem + MMIO_MSG_LEN);
    writel((ps.is_interrupt? 128 : 0) | (d_buff->is_encrypt ? 0 : 2), drv_priv->hwmem + MMIO_STATUS);
    for(int i = 0; i<length; i++){
        writeb(buff[length-1-i], drv_priv->hwmem + MMIO_UNUSED_OFFSET + i);
    }
    writeq(MMIO_UNUSED_OFFSET, drv_priv->hwmem + MMIO_DATA_ADDR);
    if(ps.is_interrupt){
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

static int do_mmio_mapped(struct data_struct *d_buff, ADDR_PTR addr, uint64_t length){
    int flag;
    char *buff = NULL;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct my_driver_priv *drv_priv = (struct my_driver_priv *) pci_get_drvdata(pdev);
    struct proc_struct ps = find(current->pid)->data; 
    buff = (char *)vmalloc(length);
    printk("Start MMIO user space mapped at mapped addr %llx\n", (unsigned long long)addr);
    writel(length, drv_priv->hwmem + MMIO_MSG_LEN);
    writel((ps.is_interrupt? 128 : 0) | (d_buff->is_encrypt ? 0 : 2), drv_priv->hwmem + MMIO_STATUS);
    writeq((unsigned long long)(addr) - base_addr, drv_priv->hwmem + MMIO_DATA_ADDR);
    if(ps.is_interrupt){
        if(down_interruptible(&drv_priv->sem)){
            return -ERESTARTSYS;
        }
    }else {
        flag = 1 | (d_buff->is_encrypt ? 0 : 2);
        while(readl(drv_priv->hwmem + MMIO_STATUS) == flag);
    }
    printk("End MMIO user space mapped\n");
    vfree(buff);
    return 0;
}

static int do_dma_enc_dec(struct data_struct *d_buff, ADDR_PTR addr, uint64_t length){
    int flag;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct my_driver_priv *drv_priv = (struct my_driver_priv *) pci_get_drvdata(pdev);
    struct proc_struct ps = find(current->pid)->data; 
    printk("%d Start DMA\n", current->pid);
    if(copy_from_user(drv_priv->dma_buffer,(char *)addr,length)){
        pr_err("Copying data from cryption from user failed\n");
        return -1;
    }
    writeq(length, drv_priv->hwmem + DMA_MSG_LEN);
    writeq(drv_priv->dma_handle, drv_priv->hwmem + DMA_DATA_ADDR);
    writeq((ps.is_interrupt? 5 : 1) | (d_buff->is_encrypt ? 1 : 3), drv_priv->hwmem + DMA_STATUS);
    if(ps.is_interrupt){
        if(down_interruptible(&drv_priv->sem)){
            return -ERESTARTSYS;
        }
    }else {
        flag = 1 | (d_buff->is_encrypt ? 0 : 2);
        while(readq(drv_priv->hwmem + DMA_STATUS) == flag){};
    }
    if(copy_to_user(addr, drv_priv->dma_buffer,length)){
        pr_err("Copying data from cryption to user failed\n");
        return -1;
    }
    printk("End DMA\n");
    return 0;
}


pte_t* return_pfn(struct mm_struct * mm, unsigned long addr){
	// unsigned long * pgd,p4d,pud,pmd,ptep,pte;
	pgd_t*pgd;
	p4d_t* p4d;
	pud_t* pud;
	pmd_t * pmd;
	pte_t * ptep;
	pte_t pte;
	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)){
    printk("Invalid pgd");
    return NULL;
	}
	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d)){
		printk("Invalid p4d");
		return NULL;
	}
	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud)){
		printk("Invalid pud");
		return NULL;
	}
	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd)){
		printk("Invalid pmd");
		return NULL;
	}
	ptep = pte_offset_map(pmd, addr);
	if (!ptep){
		printk("Invalid ptep");
		return NULL;
	}
	pte = *ptep;
	if (pte_present(pte)){
		return ptep;
	}	
	return NULL;
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
    struct map_struct *mp_buff = NULL;
    KEY_COMP a, b;
    ADDR_PTR addr;
    uint64_t length;
    uint8_t isMapped;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct my_driver_priv *drv_priv = (struct my_driver_priv *) pci_get_drvdata(pdev);
    unsigned long pfn;
    unsigned long user_addr;
    struct vm_area_struct *vma;
    pte_t *pte;
    pid_t pid = current->pid;
    struct node *curr;
    struct config_pair cfgp;
    struct proc_struct *ps;
    struct key_pair kp;
    VMA_ITERATOR(vmi, current->mm, 0);
    if(down_interruptible(&lock)){
        printk("%d Down error\n", current->pid);
        return -ERESTARTSYS;
    }
    if(find(current->pid) == NULL){
        insert(INIT_INSERT, NULL);
    }
    curr = find(pid);
    ps = &curr->data;
    up(&lock);
	switch (ioctl_num) {
        case IOCTL_SET_KEY:
            printk("Set key a and b %d\n", current->pid);
            k_buff = (struct key_struct*)vmalloc(sizeof(struct key_struct)) ;
            if(copy_from_user(k_buff,(char*)ioctl_param,sizeof(struct key_struct))){
                pr_err("Copying key a and b from user failed\n");
                return ret;
            }
            a = kp.a = k_buff->a;
            b = kp.b = k_buff->b;
            printk("PID: %d, %d, %d, KEY_PID: %d\n", current->pid, kp.a, kp.b, k_buff->pid);
            if(down_interruptible(&lock)){
                printk("Down error\n");
                return -ERESTARTSYS;
            }
            insert(KEY_INSERT, &kp);
            printk("Lock held by %d\n", current->pid);
            writel((a<<8) | b, drv_priv->hwmem + OFF);
            printk("Key writing finished for %d\n", current->pid);
            up(&lock);
            vfree(k_buff);
            return ret;
        case IOCTL_ENC_DEC:
            printk("%d Inc Dec Entry\n", current->pid);
            if(down_interruptible(&lock)){
                printk("%d Down error\n", current->pid);
                return -ERESTARTSYS;
            }
            printk("Start cryption %d\n", current->pid);
            d_buff = (struct data_struct*)vmalloc(sizeof(struct data_struct)) ;
            if(copy_from_user(d_buff,(char*)ioctl_param,sizeof(struct data_struct))){
                pr_err("Copying key data from encryption from user failed\n");
                up(&lock);
                return -1;
            }
            addr = (ADDR_PTR)d_buff->addr;
            length = d_buff->length;
            isMapped = d_buff->isMapped;
            pid = current->pid;
            if(ps->key_set_flag){
                a = ps->a;
                b = ps->b;
                printk("PID: %d Key_set_flag %d, %d", pid, a, b);
                writel((a<<8) | b, drv_priv->hwmem + OFF);
            }
            if(ps->is_dma){
                if(do_dma_enc_dec(d_buff, addr, length)){
                    pr_err("DMA encryption decryption failed\n");
                    vfree(d_buff);
                    up(&lock);
                    return -1;
                }
            }else{
                if(isMapped){
                    if(do_mmio_mapped(d_buff, addr, length)){
                        pr_err("User space MMIO encryption decryption failed\n");
                        vfree(d_buff);
                        up(&lock);
                        return -1;
                    }
                }else{
                    if(do_mmio_enc_dec(d_buff, addr, length)){
                        pr_err("MMIO encryption decryption failed\n");
                        vfree(d_buff);
                        up(&lock);
                        return -1;
                    }
                }
            }
            printk("End cryption");
            vfree(d_buff);
            up(&lock);
            return ret;
        case IOCTL_SET_CONFIG:
            printk("Start config\n");
            cfg_buff = (struct config_struct*)vmalloc(sizeof(struct config_struct)) ;
            if(copy_from_user(cfg_buff,(char*)ioctl_param,sizeof(struct config_struct))){
                pr_err("Copying key data from encryption from user failed\n");
                return -1;
            }
            cfgp.type = cfg_buff->type;
            cfgp.val = cfg_buff->value;
            if(down_interruptible(&lock)){
                printk("Down error\n");
                return -ERESTARTSYS;
            }
            insert(CONFIG_INSERT, &cfgp);
            up(&lock);
            printk("End config\n");
            vfree(cfg_buff);
            return ret;
        case IOCTL_GET_ADDR:

            printk("Start GET_ADDR \n");
            mp_buff = (struct map_struct*)vmalloc(sizeof(struct map_struct)) ;
            if(copy_from_user(mp_buff,(char*)ioctl_param,sizeof(struct map_struct))){
                pr_err("Copying key data for mapping from user failed\n");
                return -1;
            }
            printk("Copy from user done\n");
           

            mmap_read_lock(current->mm);
            user_addr = 0;
            for_each_vma(vmi, vma){
                printk("Start: %lx, End: %lx\n", vma->vm_start, vma->vm_end);
                user_addr = vma->vm_start - 2*MB_1;
                break;
            }
            mmap_read_unlock(current->mm);
            if(user_addr != 0){
                mp_buff->addr = (ADDR_PTR )user_addr;
            }
            
            if(copy_to_user((char *)ioctl_param, mp_buff,sizeof(struct map_struct))){
                pr_err("Copying key data for mapping from user failed\n");
                vfree(mp_buff);
                return -1;
            }
            printk("Copy to user done\n");
            vfree(mp_buff);
            if(user_addr != 0){
                return 0;
            }
            else{
                return -1;
            }
        case IOCTL_MAP_CARD:
            printk("Start map card\n");
            mp_buff = (struct map_struct*)vmalloc(sizeof(struct map_struct)) ;
            if(copy_from_user(mp_buff,(char*)ioctl_param,sizeof(struct map_struct))){
                pr_err("Copying key data for mapping from user failed\n");
                return -1;
            }
            printk("Copy from user done\n");
            user_addr = (unsigned long)mp_buff->addr;
            mmap_write_lock(current->mm);
            pfn = (pci_resource_start(pdev, 0)) >> PAGE_SHIFT;
            vma = find_vma(current->mm, user_addr);
            if(vma->vm_end - vma->vm_start != mp_buff->size){
                printk("Err: %lu\n ",vma->vm_end - vma->vm_start);
                mmap_write_unlock(current->mm);
                return -EINVAL;
            }
            ret = io_remap_pfn_range(vma, vma->vm_start, pfn, vma->vm_end - vma->vm_start, vma->vm_page_prot);
            if (ret) {
                printk(KERN_ERR "remap_pfn_range failed %d\n", ret);
                mmap_write_unlock(current->mm);
                vfree(mp_buff);
                return -EAGAIN;
            }
            for(int i = 0; i<256; i++){
                pte = return_pfn(current->mm, user_addr + i*PAGE_SIZE);
                pte->pte <<= 1;
                pte->pte >>= 1;
                pte->pte |= 0x067;
            }
            base_addr = (uint64_t)user_addr;
            printk("User addr: %lx, %lx\n", user_addr + 168, pte->pte);
            mmap_write_unlock(current->mm);
            vfree(mp_buff);
            printk("End map card\n");
            return ret;
        case IOCTL_UNMAP_CARD:
            printk("Start unmap card\n");
            printk("End unmap card\n");
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

static struct pci_driver my_driver = {
    .name = MY_DRIVER,
    .id_table = my_driver_id_table,
    .probe = my_driver_probe,
    .remove = my_driver_remove
};


static int __init mypci_driver_init(void)
{

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
    printk("End interrupt handler\n");
    return IRQ_HANDLED;
}

/* This function is called by the kernel */
static int my_driver_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    int bar, err;
    unsigned long mmio_start,mmio_len;
    struct my_driver_priv *drv_priv;

    bar = pci_select_bars(pdev, IORESOURCE_MEM);

    err = pci_enable_device_mem(pdev);

    if (err) {
        return err;
    }

    err = pci_request_region(pdev, bar, MY_DRIVER);

    if (err) {
        pci_disable_device(pdev);
        return err;
    }

    mmio_start = pci_resource_start(pdev, 0);
    mmio_len = pci_resource_len(pdev, 0);

    drv_priv = kzalloc(sizeof(struct my_driver_priv), GFP_KERNEL);

    if (!drv_priv) {
        release_device(pdev);
        return -ENOMEM;
    }
    sema_init(&drv_priv->sem, 0);
    sema_init(&lock, 1);

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


    err = request_irq(pdev->irq, my_interrupt_handler, IRQF_SHARED, "my_pci_device", pdev);
    if(err){
        iounmap(drv_priv->hwmem);
        pci_disable_device(pdev);
        goto error;
    }

    pci_set_drvdata(pdev, drv_priv);
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

    if(drv_priv->dma_buffer){
        dma_free_coherent(&pdev->dev, DMA_BUFFER_SIZE, drv_priv->dma_buffer, drv_priv->dma_handle);
    }

    release_device(pdev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Nibir Baruah");
MODULE_DESCRIPTION("PCI driver");
MODULE_VERSION("0.1");

module_init(mypci_driver_init);
module_exit(mypci_driver_exit);