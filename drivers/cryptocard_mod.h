#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>

#define MAJOR_NUM 100
#define DEVNAME "chardev"
#define MB_1 1048576


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

struct proc_struct{
    KEY_COMP a;
    KEY_COMP b;
    int is_dma;
    int is_interrupt;
    int key_set_flag;
};

struct hash_node {
    int pid;
    struct proc_struct* data;
    struct hash_node * next;
};

#define BUCKETS 1024

#endif