#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>

int main()
{
    DEV_HANDLE cdev;
    char *msg = "Hello World!23";
    char op_text[16];
    KEY_COMP a = 98, b = 23;
    uint64_t size = strlen(msg);
    strcpy(op_text, msg);
    cdev = create_handle();

    if (cdev == ERROR)
    {
        printf("Unable to create handle for device\n");
        exit(0);
    }

    printf("Original Text: %s\n", msg);

    int keys[5][2] = { {2, 45},
                       {37, 43},
                       {24, 24},
                       {12, 135},
                       {4, 45} };
    
    for(int i = 0; i<5; i++){
        if (set_key(cdev, keys[i][0], keys[i][1]) == ERROR)
        {
            printf("Unable to set key\n");
            exit(0);
        }
        else{
            printf("key set: %d, %d\n", keys[i][0], keys[i][1]);
        }

        encrypt(cdev, op_text, size, 0);
        printf("Encrypted Text: %s\n", op_text);
    }

    for(int i = 0; i<5; i++){
        if (set_key(cdev, keys[4-i][0], keys[4-i][1]) == ERROR)
        {
            printf("Unable to set key\n");
            exit(0);
        }
        else{
            printf("key set: %d, %d\n", keys[4-i][0], keys[4-i][1]);
        }

        decrypt(cdev, op_text, size, 0);
        printf("Decrypted Text: %s\n", op_text);
    }

    close_handle(cdev);
    return 0;
}
