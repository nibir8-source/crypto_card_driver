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
#include "util.h"


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

static ssize_t device_write(struct file *filp, const char *buff, size_t len, loff_t * off){ 
    printk("write called\n");
    return 0;
}



static int Dma_encrypt_decrypt(struct data *data_buffer, ADDR_PTR addr, uint64_t length){
    int flag;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct per_driver_data *drv_priv = (struct per_driver_data *) pci_get_drvdata(pdev);

    if(copy_from_user(drv_priv->dma_buffer,(char *)addr,length)){
        pr_err("Copying data from cryption from user failed\n");
        return -1;
    }

    writeq(length, drv_priv->hwmem + OFF_DMA_MSG_LEN);
    writeq(drv_priv->dma_handle, drv_priv->hwmem + OFF_DMA_DATA_ADDR);
    writeq((ps[current->pid].is_interrupt? 5 : 1) | (data_buffer->is_encrypt ? 1 : 3), drv_priv->hwmem + OFF_DMA_STATUS);


    if(ps[current->pid].is_interrupt){
        if(down_interruptible(&drv_priv->sem)){
            return -ERESTARTSYS;
        }
    }
    else {
        flag = 1 | (data_buffer->is_encrypt ? 0 : 2);
        while(readq(drv_priv->hwmem + OFF_DMA_STATUS) == flag){};
    }

    if(copy_to_user(addr, drv_priv->dma_buffer,length)){
        pr_err("Copying data from cryption to user failed\n");
        return -1;
    }

    return 0;
}

static int Mmio_Mapped(struct data *data_buffer, ADDR_PTR addr, uint64_t length){
    int flag;
    char *buff = NULL;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct per_driver_data *drv_priv = (struct per_driver_data *) pci_get_drvdata(pdev);
    buff = (char *)vmalloc(length);

    writel(length, drv_priv->hwmem + OFF_MMIO_MSG_LEN);
    writel((ps[current->pid].is_interrupt? 128 : 0) | (data_buffer->is_encrypt ? 0 : 2), drv_priv->hwmem + OFF_MMIO_STATUS);
    writeq((unsigned long long)(addr) - base_addr, drv_priv->hwmem + OFF_MMIO_DATA_ADDR);
    if(ps[current->pid].is_interrupt){
        if(down_interruptible(&drv_priv->sem)){
            return -ERESTARTSYS;
        }
    }
    else {
        flag = 1 | (data_buffer->is_encrypt ? 0 : 2);
        while(readl(drv_priv->hwmem + OFF_MMIO_STATUS) == flag);
    }

    vfree(buff);
    return 0;
}

static int Mmio_encrypt_decrypt(struct data *data_buffer, ADDR_PTR addr, uint64_t length){
    int flag;
    char *buff = NULL;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct per_driver_data *drv_priv = (struct per_driver_data *) pci_get_drvdata(pdev);

    buff = (char *)vmalloc(length);

    if(copy_from_user(buff,(char *)addr,length)){
        pr_err("Copying data from cryption from user failed\n");
        return -1;
    }

    writel(length, drv_priv->hwmem + OFF_MMIO_MSG_LEN);
    writel((ps[current->pid].is_interrupt? 128 : 0) | (data_buffer->is_encrypt ? 0 : 2), drv_priv->hwmem + OFF_MMIO_STATUS);

    for(int i = 0; i<length; i++){
        writeb(buff[length-1-i], drv_priv->hwmem + OFF_MMIO_UNUSED + i);
    }

    writeq(OFF_MMIO_UNUSED, drv_priv->hwmem + OFF_MMIO_DATA_ADDR);

    if(ps[current->pid].is_interrupt){
        if(down_interruptible(&drv_priv->sem)){
            return -ERESTARTSYS;
        }
    }
    else {
        flag = 1 | (data_buffer->is_encrypt ? 0 : 2);
        while(readl(drv_priv->hwmem + OFF_MMIO_STATUS) == flag);
    }

    for(int i = 0; i<length; i++){
        buff[length-1-i] = readb(drv_priv->hwmem + OFF_MMIO_UNUSED + i);
    }

    if(copy_to_user(addr, buff,length)){
        pr_err("Copying data from cryption to user failed\n");
        return -1;
    }

    return 0;
}

int ioctl_set_key_func(unsigned long ioctl_param,struct per_driver_data *drv_priv){
    int ret = 0;
    pid_t pid;
    struct s_key *key_buffer = NULL;
    KEY_COMP a, b;
    key_buffer = (struct s_key*)vmalloc(sizeof(struct s_key)) ;
    if(copy_from_user(key_buffer,(char*)ioctl_param,sizeof(struct s_key))){
        pr_err("Copying key a and b from user failed\n");
        return ret;
    }

    a = key_buffer->a;
    b = key_buffer->b;

    if(down_interruptible(&lock)){
        printk("Down error\n");
        return -ERESTARTSYS;
    }

    pid = current->pid;
    ps[pid].a = a;
    ps[pid].b = b;
    ps[pid].key_set_flag = 1;
    writel((a<<8) | b, drv_priv->hwmem + OFF_KEY);
    up(&lock);
    vfree(key_buffer);
    return ret;

}

int ioctl_enc_dec_func(unsigned long ioctl_param, struct per_driver_data *drv_priv) {
    struct data *data_buffer = NULL;
    int ret=0;
    ADDR_PTR addr;
    uint64_t length;
    uint8_t isMapped;
    pid_t pid;
    KEY_COMP a, b;
    if(down_interruptible(&lock)){
        return -ERESTARTSYS;
    }
    data_buffer = (struct data*)vmalloc(sizeof(struct data)) ;

    if(copy_from_user(data_buffer,(char*)ioctl_param,sizeof(struct data))){
        pr_err("Copying key data from encryption from user failed\n");
        up(&lock);
        return -1;
    }

    addr = (ADDR_PTR)data_buffer->addr;
    length = data_buffer->length;
    isMapped = data_buffer->isMapped;
    pid = current->pid;

    if(ps[pid].key_set_flag){
        a = ps[pid].a;
        b = ps[pid].b;
        writel((a<<8) | b, drv_priv->hwmem + OFF_KEY);
    }
    if(ps[pid].is_dma){
        if(Dma_encrypt_decrypt(data_buffer, addr, length)){
            pr_err("DMA encryption decryption failed\n");
            vfree(data_buffer);
            up(&lock);
            return -1;
        }
    }else{
        if(isMapped){
            if(Mmio_Mapped(data_buffer, addr, length)){
                pr_err("User space MMIO encryption decryption failed\n");
                vfree(data_buffer);
                up(&lock);
                return -1;
            }
        }
        else{
            if(Mmio_encrypt_decrypt(data_buffer, addr, length)){
                pr_err("MMIO encryption decryption failed\n");
                vfree(data_buffer);
                up(&lock);
                return -1;
            }
        }
    }
    vfree(data_buffer);
    up(&lock);
    return ret;
}


int ioctl_set_config(unsigned long ioctl_param){
    struct config *config_buffer = NULL;
    config_t type;
    uint8_t value;
    int ret;
    pid_t pid= current->pid;
    ret = 0;
    config_buffer = (struct config*)vmalloc(sizeof(struct config)) ;
    if(copy_from_user(config_buffer,(char*)ioctl_param,sizeof(struct config))){
        pr_err("Copying key data from encryption from user failed\n");
        return -1;
    }
    type = config_buffer->type;
    value = config_buffer->value;
    if(type == INTERRUPT){
        ps[pid].is_interrupt = value;
    }else{
        ps[pid].is_dma = value;
    }
    vfree(config_buffer);
    return ret;

}

int ioctl_get_addr(unsigned long ioctl_param){
    struct map *map_buffer = NULL;
    unsigned long user_addr;
    struct vm_area_struct *vma;
    VMA_ITERATOR(vmi, current->mm, 0);

    map_buffer = (struct map*)vmalloc(sizeof(struct map)) ;
    if(copy_from_user(map_buffer,(char*)ioctl_param,sizeof(struct map))){
        pr_err("Copying key data for mapping from user failed\n");
        return -1;
    }
    
    mmap_read_lock(current->mm);
    user_addr = 0;
    for_each_vma(vmi, vma){
        user_addr = vma->vm_start - 2*1024*1024;
        break;
    }
    mmap_read_unlock(current->mm);
    if(user_addr != 0){
        map_buffer->addr = (ADDR_PTR )user_addr;
    }
    
    if(copy_to_user((char *)ioctl_param, map_buffer,sizeof(struct map))){
        pr_err("Copying key data for mapping from user failed\n");
        vfree(map_buffer);
        return -1;
    }
    vfree(map_buffer);
    if(user_addr != 0){
        return 0;
    }
    else{
        return -1;
    }

}


int ioctl_map_card(unsigned long ioctl_param,struct pci_dev *pdev){
    int ret = 0;
    struct map *map_buffer = NULL;
    unsigned long user_addr;
    unsigned long pfn;
    struct vm_area_struct *vma;

    pte_t *pte;

    map_buffer = (struct map*)vmalloc(sizeof(struct map)) ;
    if(copy_from_user(map_buffer,(char*)ioctl_param,sizeof(struct map))){
        pr_err("Copying key data for mapping from user failed\n");
        return -1;
    }

    user_addr = (unsigned long)map_buffer->addr;
    mmap_write_lock(current->mm);
    pfn = (pci_resource_start(pdev, 0)) >> PAGE_SHIFT;
    vma = find_vma(current->mm, user_addr);
    if(vma->vm_end - vma->vm_start != map_buffer->size){
        // printk("Err: %lu\n ",vma->vm_end - vma->vm_start);
        mmap_write_unlock(current->mm);
        return -EINVAL;
    }
    ret = io_remap_pfn_range(vma, vma->vm_start, pfn, vma->vm_end - vma->vm_start, vma->vm_page_prot);
    if (ret) {
        mmap_write_unlock(current->mm);
        vfree(map_buffer);
        return -EAGAIN;
    }
    for(int i = 0; i<256; i++){
        pte = Page_table_walker(current->mm, user_addr + i*PAGE_SIZE);
        pte->pte <<= 1;
        pte->pte >>= 1;
        pte->pte |= 0x067;
    }
    base_addr = (uint64_t)user_addr;

    mmap_write_unlock(current->mm);
    vfree(map_buffer);
    return ret;

}

long device_ioctl(struct file *file,unsigned int ioctl_num, unsigned long ioctl_param)
{
	int ret = 0;
    struct pci_dev *pdev = pci_get_device(CRYPTOCARD_VENDOR_ID, CRYPTOCARD_DEVICE_ID, NULL);
    struct per_driver_data *drv_priv = (struct per_driver_data *) pci_get_drvdata(pdev);

    if(ioctl_num == IOCTL_SETKEY){
            ret = ioctl_set_key_func(ioctl_param,drv_priv);
            return ret;
    }
    else if (ioctl_num == IOCTL_ENCRYPT_DECRYPT){
            ret = ioctl_enc_dec_func(ioctl_param,drv_priv);
            return ret;
    }
    else if(ioctl_num == IOCTL_SETCONFIG){
            ret = ioctl_set_config(ioctl_param);
            return ret;
    }
    else if(ioctl_num ==IOCTL_GETADDR){       
            ret= ioctl_get_addr(ioctl_param);
    }
    else if(ioctl_num ==IOCTL_MAPCARD){
            ret = ioctl_map_card(ioctl_param,pdev);
            return ret;
    }

    else if(ioctl_num ==IOCTL_UNMAPCARD){
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

static int pci_driver_probe(struct pci_dev *pdev, const struct pci_device_id *ent);
static void pci_driver_remove(struct pci_dev *pdev);

/* Driver registration structure */
static struct pci_driver my_driver = {
    .name = MY_DRIVER,
    .id_table = my_driver_id_table,
    .probe = pci_driver_probe,
    .remove = pci_driver_remove
};


static int __init pci_driver_init(void)
{
    /* Register new PCI driver */

    int err;

    initialise_per_process_req_info();
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

static void __exit pci_driver_exit(void)
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
    struct per_driver_data *drv_priv = (struct per_driver_data *) pci_get_drvdata(pdev);
    u32 isr;
    isr = readl(drv_priv->hwmem + OFF_ISR);
    writel(isr, drv_priv->hwmem + OFF_ACK);
    up(&drv_priv->sem);
    return IRQ_HANDLED;
}

/* This function is called by the kernel */
static int pci_driver_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    //taken from https://olegkutkov.me/2021/01/07/writing-a-pci-device-driver-for-linux/
    int bar, err;
    u16 vendor, device;
    unsigned long mmio_start,mmio_len;
    struct per_driver_data *drv_priv;

    /* Let's read data from the PCI device configuration registers */
    pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor);
    pci_read_config_word(pdev, PCI_DEVICE_ID, &device);

    printk(KERN_INFO "Device vid: 0x%X pid: 0x%X\n", vendor, device);
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

    drv_priv = kzalloc(sizeof(struct per_driver_data), GFP_KERNEL);

    if (!drv_priv) {
        release_device(pdev);
        return -ENOMEM;
    }
    sema_init(&drv_priv->sem, 0);
    sema_init(&lock, 1);

    drv_priv->hwmem = ioremap(mmio_start, mmio_len);

    if (!drv_priv->hwmem) {
       release_device(pdev);
       return -EIO;
    }

    err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
    if(err){
        dev_err(&pdev->dev, "Failed to set DMA mask for device\n");
        goto error;
    }

    drv_priv->dma_buffer = dma_alloc_coherent(&pdev->dev, OFF_DMA_BUFFER_SIZE, &drv_priv->dma_handle, GFP_KERNEL);
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
        dma_free_coherent(&pdev->dev, OFF_DMA_BUFFER_SIZE, drv_priv->dma_buffer, drv_priv->dma_handle);
    }
    return err;
}

static void pci_driver_remove(struct pci_dev *pdev)
{
    struct per_driver_data *drv_priv = pci_get_drvdata(pdev);

    if (drv_priv) {
        if (drv_priv->hwmem) {
            iounmap(drv_priv->hwmem);
        }
        kfree(drv_priv);
    }
    free_irq(pdev->irq, pdev);
    if(drv_priv->dma_buffer){
        dma_free_coherent(&pdev->dev, OFF_DMA_BUFFER_SIZE, drv_priv->dma_buffer, drv_priv->dma_handle);
    }
    release_device(pdev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manish");
MODULE_DESCRIPTION("PCI driver");
MODULE_VERSION("0.1");

module_init(pci_driver_init);
module_exit(pci_driver_exit);