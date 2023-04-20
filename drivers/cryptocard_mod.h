#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>

#define MAJOR_NUM 100
#define DEVNAME "chardev"
#define ONE_MB 1024*1024


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

#define IOCTL_SET_KEY _IOWR(MAJOR_NUM, 0, char*)
#define IOCTL_ENC_DEC _IOWR(MAJOR_NUM, 1, char*)
#define IOCTL_SET_CONFIG _IOWR(MAJOR_NUM, 2, char*)
#define IOCTL_MAP_CARD _IOWR(MAJOR_NUM, 3, char*)
#define IOCTL_GET_ADDR _IOWR(MAJOR_NUM, 4, char*)

typedef enum {INTERRUPT, DMA} config_t;


typedef void* ADDR_PTR;
typedef int DEV_HANDLE;
typedef unsigned char KEY_COMP;

struct key_struct{
  KEY_COMP a;
  KEY_COMP b;
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

struct mmap_struct{
  ADDR_PTR addr;
  uint64_t size;
};

#endif