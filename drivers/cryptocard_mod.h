#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>

#define MAJOR_NUM 100
#define DEVNAME "chardev"


#define IOCTL_SET_KEY _IOWR(MAJOR_NUM, 0, char*)
#define IOCTL_ENC_DEC _IOWR(MAJOR_NUM, 1, char*)
#define IOCTL_SET_CONFIG _IOWR(MAJOR_NUM, 2, char*)

typedef enum {INTERRUPT, DMA} config_t;

#endif