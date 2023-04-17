#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>

int main()
{
    DEV_HANDLE cdev = create_handle();
    char *msg = "Hello CS7349!";
    KEY_COMP a = 30, b = 17;
    uint64_t size = strlen(msg);
    set_config(cdev, DMA, 0);   // MMAP only valid in MMIO mode
    set_config(cdev, INTERRUPT, 0); // This test case is w/o interrupts
    set_key(cdev, a, b);
    char *actual_buff = map_card(cdev, size); // Return a pointer mapped to the device memory
    printf("Addr: %p\n", actual_buff);
    strncpy(actual_buff, msg, size);
    printf("Actual text: %lu %lu %s\n", size, strlen(actual_buff), actual_buff);
    encrypt(cdev, actual_buff, size, 1); // Last argument is 1 ==> it is mapped
    printf("Encrypted text: %s\n", actual_buff);
    decrypt(cdev, actual_buff, size, 1); // Last argument is 1 ==> it is mapped
    printf("Decrypted text: %s\n", actual_buff);
    // At this point, "actual_buf" contains the encrypted message
    unmap_card(cdev, actual_buff);
    close_handle(cdev);
}