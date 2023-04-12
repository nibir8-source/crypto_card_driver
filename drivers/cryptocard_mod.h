#ifndef CHARDEV_H
#define CHARDEV_H

#include <linux/ioctl.h>

#define MAJOR_NUM 100
#define DEVNAME "chardev"


#define IOCTL_SET_KEY _IOWR(MAJOR_NUM, 0, char*)
#define IOCTL_ENCRYPT _IOWR(MAJOR_NUM, 1, char*)
#define IOCTL_DECRYPT _IOWR(MAJOR_NUM, 2, char*)

#endif