#include<crypter.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/fcntl.h>
#include<signal.h>
#include<sys/ioctl.h>
#include<sys/mman.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define MAJOR_NUM 100


#define IOCTL_SET_KEY _IOR(MAJOR_NUM, 0, char*)
#define IOCTL_ENCRYPT _IOWR(MAJOR_NUM, 1, char*)
#define IOCTL_DECRYPT _IOWR(MAJOR_NUM, 2, char*)

struct key_struct{
  KEY_COMP a;
  KEY_COMP b;
};

struct data_struct{
  ADDR_PTR addr;
  uint64_t length;
  uint8_t isMapped;
};

struct key_struct k_struct;

/*Function template to create handle for the CryptoCard device.
On success it returns the device handle as an integer*/
DEV_HANDLE create_handle()
{
  DEV_HANDLE fd = open("/dev/chardev",O_RDWR);
  if(fd < 0){
      return ERROR;
  }
  return fd;
}

/*Function template to close device handle.
Takes an already opened device handle as an arguments*/
void close_handle(DEV_HANDLE cdev)
{
  close(cdev);
}

/*Function template to encrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which encryption has to be performed
  length: size of data to be encrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
  struct data_struct d_struct;
  d_struct.addr = addr;
  d_struct.length = length;
  d_struct.isMapped = isMapped;
  if(ioctl(cdev, IOCTL_ENCRYPT, &d_struct) < 0){
       return ERROR;
  }
  return 0;
}

/*Function template to decrypt a message using MMIO/DMA/Memory-mapped.
Takes four arguments
  cdev: opened device handle
  addr: data address on which decryption has to be performed
  length: size of data to be decrypt
  isMapped: TRUE if addr is memory-mapped address otherwise FALSE
*/
int decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
  struct data_struct d_struct;
  d_struct.addr = addr;
  d_struct.length = length;
  d_struct.isMapped = isMapped;
  if(ioctl(cdev, IOCTL_DECRYPT, &d_struct) < 0){
       return ERROR;
  }
  return 0;
}

/*Function template to set the key pair.
Takes three arguments
  cdev: opened device handle
  a: value of key component a
  b: value of key component b
Return 0 in case of key is set successfully*/
int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b)
{
  k_struct.a = a;
  k_struct.b = b;
  printf("FD: %d %lu %d %d\n", cdev, IOCTL_SET_KEY, k_struct.a, k_struct.b);
  if(ioctl(cdev, IOCTL_SET_KEY, &k_struct) < 0){
       return ERROR;
  }
  return 0;
}

/*Function template to set configuration of the device to operate.
Takes three arguments
  cdev: opened device handle
  type: type of configuration, i.e. set/unset DMA operation, interrupt
  value: SET/UNSET to enable or disable configuration as described in type
Return 0 in case of key is set successfully*/
int set_config(DEV_HANDLE cdev, config_t type, uint8_t value)
{
  return ERROR;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  size: amount of memory-mapped into user-space (not more than 1MB strict check)
Return virtual address of the mapped memory*/
ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size)
{
  return NULL;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  addr: memory-mapped address to unmap from user-space*/
void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr)
{

}
