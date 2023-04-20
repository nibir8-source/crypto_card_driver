#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>

int main()
{
    DEV_HANDLE cdev = create_handle();
    char *msg = "Hello CS241@#!"; 
    char *msg_2 = "yNbnNj qwrwas";
    char *msg_3 = "TOm DCD3Q!?";
    KEY_COMP a = 120, b = 125;
    uint64_t size = strlen(msg);
    set_config(cdev, DMA, 0);   // MMAP only valid in MMIO mode
    set_config(cdev, INTERRUPT, 0); // This test case is w/o interrupts
    set_key(cdev, a, b);
    char *actual_buff = map_card(cdev, size); // Return a pointer mapped to the device memory
    char *actual_buff_2 = map_card(cdev, size);
    printf("Addr: %p\n", actual_buff_2);
    strncpy(actual_buff_2, msg_2, size);
    printf("Actual text: %lu %lu %s\n", size, strlen(actual_buff_2), actual_buff_2);
    encrypt(cdev, actual_buff_2, size, 1); // Last argument is 1 ==> it is mapped
    printf("Encrypted text: %s\n", actual_buff_2);
    decrypt(cdev, actual_buff_2, size, 1); // Last argument is 1 ==> it is mapped
    printf("Decrypted text: %s\n", actual_buff_2);
    unmap_card(cdev, actual_buff_2);
    char *actual_buff_3 = map_card(cdev, size);
    printf("Addr: %p\n", actual_buff_3);
    strncpy(actual_buff_3, msg_3, size);
    printf("Actual text: %lu %lu %s\n", size, strlen(actual_buff_3), actual_buff_3);
    encrypt(cdev, actual_buff_3, size, 1); // Last argument is 1 ==> it is mapped
    printf("Encrypted text: %s\n", actual_buff_3);
    decrypt(cdev, actual_buff_3, size, 1); // Last argument is 1 ==> it is mapped
    printf("Decrypted text: %s\n", actual_buff_3);
    unmap_card(cdev, actual_buff_3);
    printf("Addr: %p\n", actual_buff);
    strncpy(actual_buff, msg, size);
    printf("Actual text: %lu %lu %s\n", size, strlen(actual_buff), actual_buff);
    encrypt(cdev, actual_buff, size, 1); // Last argument is 1 ==> it is mapped
    printf("Encrypted text: %s\n", actual_buff);
    decrypt(cdev, actual_buff, size, 1); // Last argument is 1 ==> it is mapped
    printf("Decrypted text: %s\n", actual_buff);
    unmap_card(cdev, actual_buff);
    close_handle(cdev);
}