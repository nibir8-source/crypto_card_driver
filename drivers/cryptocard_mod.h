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
#define IOCTL_UNMAP_CARD _IOWR(MAJOR_NUM, 4, char*)
#define IOCTL_GET_ADDR _IOWR(MAJOR_NUM, 5, char*)

typedef enum {INTERRUPT, DMA} config_t;

#endif