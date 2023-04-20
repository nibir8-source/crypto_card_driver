#include <crypter.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define MB_1 1048576

struct key_struct
{
  KEY_COMP a;
  KEY_COMP b;
  int pid;
};

struct data_struct
{
  uint64_t addr;
  uint64_t length;
  uint8_t isMapped;
  int is_encrypt;
};

struct config_struct
{
  config_t type;
  uint8_t value;
};

struct map_struct
{
  ADDR_PTR addr;
  uint64_t size;
};

uint64_t mmap_size;
int map_count = 0;
uint64_t addr_start, addr_org;

/*Function template to create handle for the CryptoCard device.
On success it returns the device handle as an integer*/
DEV_HANDLE create_handle()
{
  DEV_HANDLE fd = open("/dev/chardev", O_RDWR);
  if (fd < 0)
  {
    return ERROR;
  }
  map_count = 0;
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
#define KB_512 512 * 1024

int enc_dec(DEV_HANDLE cdev, unsigned long long addr, uint64_t length, uint8_t isMapped, int is_encrypt){
  
  struct data_struct d_struct;
  uint64_t start = addr;
  while(start + KB_512 <= addr + length){
    d_struct.addr = (uint64_t)(start);
    d_struct.length = KB_512;
    d_struct.isMapped = isMapped;
    d_struct.is_encrypt = is_encrypt;
    if (ioctl(cdev, IOCTL_ENC_DEC, &d_struct) < 0)
    {
      return ERROR;
    }
    start += KB_512;
  }
  if(start < addr + length){
    d_struct.addr = (uint64_t)(start);
    d_struct.length = addr + length - start;
    d_struct.isMapped = isMapped;
    d_struct.is_encrypt = is_encrypt;
    if (ioctl(cdev, IOCTL_ENC_DEC, &d_struct) < 0)
    {
      return ERROR;
    }
  }
  return 0;

}

int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
  if(enc_dec(cdev, (unsigned long long)addr, length, isMapped, 1)<0){
    return -1;
  }
  else{
    return 0;
  }
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
  if(enc_dec(cdev, (unsigned long long)addr, length, isMapped, 0)<0){
    return -1;
  }
  else{
    return 0;
  }
}

/*Function template to set the key pair.
Takes three arguments
  cdev: opened device handle
  a: value of key component a
  b: value of key component b
Return 0 in case of key is set successfully*/
int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b)
{
  struct key_struct k_struct;
  k_struct.a = a;
  k_struct.b = b;
  k_struct.pid = getpid();
  if (ioctl(cdev, IOCTL_SET_KEY, &k_struct) < 0)
  {
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
  struct config_struct cfg;
  cfg.type = type;
  cfg.value = value;
  if (ioctl(cdev, IOCTL_SET_CONFIG, &cfg) < 0)
  {
    return ERROR;
  }
  return 0;
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  size: amount of memory-mapped into user-space (not more than 1MB strict check)
Return virtual address of the mapped memory*/
ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size)
{
  if (size > MB_1)
  {
    printf("Size more than 1 MB\n");
    return NULL;
  }
  if(size%4){
    size += 4 - (size % 4);
  }
  if(map_count != 0){
    ADDR_PTR addr = (ADDR_PTR)addr_start;
    map_count++;
    addr_start += size;
    return addr;
  }
  
  struct map_struct mp;
  mp.size = mmap_size = MB_1;
  if (ioctl(cdev, IOCTL_GET_ADDR, &mp) < 0)
  {
    printf("Unable to get address\n");
    return NULL;
  }

  ADDR_PTR addr = mmap(mp.addr, mp.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
  if (addr != mp.addr)
  {
    printf("Unable to do mmap\n");
    return NULL;
  }
  if (ioctl(cdev, IOCTL_MAP_CARD, &mp) < 0)
  {
    printf("Unable to do ioctl_map_card\n");
    return NULL;
  }
  map_count++;
  addr_start = (unsigned long long)mp.addr + 168 + size;
  addr_org = (unsigned long long)mp.addr;
  return (mp.addr + 168);
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  addr: memory-mapped address to unmap from user-space*/
void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr)
{
  if(map_count > 0){
    map_count--;
  }
  if(map_count == 0){
    munmap((ADDR_PTR)addr_org, MB_1);
  }
}
