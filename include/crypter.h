#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>


#ifndef CRYPTER_H_
#define CRYPTER_H_

typedef void* ADDR_PTR;
typedef int DEV_HANDLE;
typedef unsigned char KEY_COMP;

#define SET 1
#define UNSET 0
#define TRUE 1
#define FALSE 0
#define ERROR -1

#define MAJOR_NUM 100


#define IOCTL_SET_KEY _IOWR(MAJOR_NUM, 0, char*)
#define IOCTL_ENC_DEC _IOWR(MAJOR_NUM, 1, char*)
#define IOCTL_SET_CONFIG _IOWR(MAJOR_NUM, 2, char*)
#define IOCTL_MAP_CARD _IOWR(MAJOR_NUM, 3, char*)
#define IOCTL_UNMAP_CARD _IOWR(MAJOR_NUM, 4, char*)
#define IOCTL_GET_ADDR _IOWR(MAJOR_NUM, 5, char*)

typedef enum {INTERRUPT, DMA} config_t;

DEV_HANDLE create_handle();

void close_handle(DEV_HANDLE cdev);

int encrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped);

int decrypt(DEV_HANDLE cdev, ADDR_PTR addr, uint64_t length, uint8_t isMapped);

int set_key(DEV_HANDLE cdev, KEY_COMP a, KEY_COMP b);

int set_config(DEV_HANDLE cdev, config_t type, uint8_t value);

ADDR_PTR map_card(DEV_HANDLE cdev, uint64_t size);

void unmap_card(DEV_HANDLE cdev, ADDR_PTR addr);


// Extra Definitions 
typedef unsigned long long ull;
typedef unsigned long ul;
typedef unsigned char uc;


#define ONE_MB 1024*1024
#define OFFSET 168

struct key
{
  KEY_COMP a;
  KEY_COMP b;
  pid_t pid;
};

void initialise_key(struct key *temp, KEY_COMP a, KEY_COMP b, pid_t pid)
{
    temp->a =  a;
    temp->b = b;
    temp->pid = pid;

}

struct data
{
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

struct config
{
  config_t type;
  uc value;
};

void initialise_config(struct config * temp, config_t type, uc value){
    temp->type = type;
    temp->value = value;

}

struct map
{
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



ul mmap_size;
ul map_count = 0;
ul addr_start, addr_org;

#endif
