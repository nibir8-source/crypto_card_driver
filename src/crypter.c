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

/*Function template to create handle for the CryptoCard device.
On success it returns the device handle as an integer*/
int used_count = 0;

DEV_HANDLE create_handle()
{
  DEV_HANDLE fd = open("/dev/chardev", O_RDWR);
  if (fd < 0)
  {
    return ERROR;
  }
  used_count = 0;
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
#define HALF_MB 512 * 1024

int helper(DEV_HANDLE cdev, unsigned long long addr, uint64_t length, uint8_t isMapped, int is_encrypt)
{

  struct data_struct d_struct;
  uint64_t start = addr;
  while (start + HALF_MB <= addr + length)
  {
    d_struct.addr = (uint64_t)(start);
    d_struct.length = HALF_MB;
    d_struct.isMapped = isMapped;
    d_struct.is_encrypt = is_encrypt;
    // printf("Encrypting data at %llu, LEN: %lu, %d\n", start, HALF_MB, isMapped);
    if (ioctl(cdev, IOCTL_ENC_DEC, &d_struct) < 0)
    {
      return ERROR;
    }
    start += HALF_MB;
  }
  if (start < addr + length)
  {
    d_struct.addr = (uint64_t)(start);
    d_struct.length = addr + length - start;
    d_struct.isMapped = isMapped;
    d_struct.is_encrypt = is_encrypt;
    // printf("Encrypting data at %llu, LEN: %lu, %d\n", start, d_struct.length, isMapped);
    if (ioctl(cdev, IOCTL_ENC_DEC, &d_struct) < 0)
    {
      return ERROR;
    }
  }
  return 0;
}

int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped)
{
  return helper(cdev, (unsigned long long)addr, length, isMapped, ENCRYPT);
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
  return helper(cdev, (unsigned long long)addr, length, isMapped, DECRYPT);
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
  // printf("In set_key userspace FD: %d %lu %d %d\n", cdev, IOCTL_SET_KEY, k_struct.a, k_struct.b);
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

#define ONE_MB 1024 * 1024
uint64_t addr_offset, addr_base;

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  size: amount of memory-mapped into user-space (not more than 1MB strict check)
Return virtual address of the mapped memory*/
ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size)
{
  if (size + UNUSED_OFF > ONE_MB)
  {
    printf("Requested + Used size more than 1 MB\n");
    return NULL;
  }
  // Pad size
  size += (4 - (size % 4)) * ((size % 4) != 0);
  if (used_count != 0)
  {
    ADDR_PTR addr = (ADDR_PTR)addr_offset;
    used_count++;
    addr_offset += size;
    return addr;
  }
  else
  {
    struct mmap_struct mp;
    mp.size = ONE_MB;
    if (ioctl(cdev, IOCTL_GET_ADDR, &mp) < 0)
    {
      printf("Unable to get userspace virtual address\n");
      return NULL;
    }
    // Do fixed mmap at that address
    ADDR_PTR addr = mmap(mp.addr, mp.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0, 0);
    if (addr != mp.addr)
    {
      printf("Unable to do mmap at fixed address\n");
      return NULL;
    }
    if (ioctl(cdev, IOCTL_MAP_CARD, &mp) < 0)
    {
      printf("Unable to do ioctl map card\n");
      return NULL;
    }
    used_count++;
    addr_offset = (uint64_t)mp.addr + UNUSED_OFF + size;
    addr_base = (uint64_t)mp.addr;
    return (mp.addr + UNUSED_OFF);
  }
}

/*Function template to device input/output memory into user space.
Takes three arguments
  cdev: opened device handle
  addr: memory-mapped address to unmap from user-space*/
void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr)
{
  if(used_count == 1){
    used_count = 0;
    munmap((void *)addr_base, ONE_MB);
  }
  else if(used_count > 1){
    used_count--;
  }
}
