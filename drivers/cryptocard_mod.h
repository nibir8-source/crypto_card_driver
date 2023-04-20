#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>

#define MAJOR_NUM 100
#define DEVNAME "chardev"
#define MB_1 1048576

typedef enum {INTERRUPT, DMA} config_t;


//Extra Definitions 

#define MY_DRIVER "cryptocard_pci_driver"
#define DEVNAME "chardev"
#define OFF_KEY 8
#define OFF_MMIO_MSG_LEN 12
#define OFF_MMIO_STATUS 32
#define OFF_ISR 36
#define OFF_ACK 100
#define OFF_MMIO_DATA_ADDR 128
#define OFF_DMA_DATA_ADDR 144
#define OFF_DMA_MSG_LEN 152
#define OFF_DMA_STATUS 160
#define OFF_MMIO_UNUSED 168


#define OFF_DMA_BUFFER_SIZE PAGE_SIZE
#define MAX_PID 4194304


#define CRYPTOCARD_VENDOR_ID 0x1234
#define CRYPTOCARD_DEVICE_ID 0xDEBA
#define IOCTL_SETKEY _IOWR(MAJOR_NUM, 0, char*)
#define IOCTL_ENCRYPT_DECRYPT _IOWR(MAJOR_NUM, 1, char*)
#define IOCTL_SETCONFIG _IOWR(MAJOR_NUM, 2, char*)
#define IOCTL_MAPCARD _IOWR(MAJOR_NUM, 3, char*)
#define IOCTL_UNMAPCARD _IOWR(MAJOR_NUM, 4, char*)
#define IOCTL_GETADDR _IOWR(MAJOR_NUM, 5, char*)

typedef void* ADDR_PTR;
typedef int DEV_HANDLE;
typedef unsigned char KEY_COMP;
typedef unsigned long long ull;
typedef unsigned long ul;
typedef unsigned char uc;

static int major;
atomic_t  device_opened;
static struct class *demo_class;
struct device *demo_device;

struct s_key{
  KEY_COMP a;
  KEY_COMP b;
  pid_t pid;
};

void initialise_key(struct s_key *temp, KEY_COMP a, KEY_COMP b, pid_t pid)
{
    temp->a =  a;
    temp->b = b;
    temp->pid = pid;

}

struct data{
  ul addr;
  ul length;
  uc isMapped;
  int is_encrypt;
};

void initialise_data(struct data * temp, ul addr, ul length, uc isMapped, int is_encrypt){
    temp->addr =addr;
    temp->length = length;
    temp->isMapped = isMapped;
    temp->is_encrypt = is_encrypt;
}


struct config{
  config_t type;
  uint8_t value;
};

void initialise_config(struct config * temp, config_t type, uc value){
    temp->type = type;
    temp->value = value;

}


struct map{
  ADDR_PTR addr;
  ul size;
};


void initialise_map(struct map *temp, ADDR_PTR addr, ul size){
    temp->addr= addr;
    temp->size=size;
}

void initialise_half_map(struct map *temp,ul size){
    temp->size=size;
}

struct semaphore lock;

struct per_driver_data {
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

struct per_process_req_info{
    KEY_COMP a;
    KEY_COMP b;
    int is_dma;
    int is_interrupt;
    int key_set_flag;
};

struct per_process_req_info ps[MAX_PID];


void initialise_per_process_req_info(void){
    for(int i = 0; i<MAX_PID; i++){
        ps[i].is_interrupt = ps[i].is_dma = 0;
        ps[i].key_set_flag = 0;
    }
}

#endif