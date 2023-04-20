#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>
#include <pthread.h>

#define NUM_THREADS 10

struct thread_struct
{
    DEV_HANDLE cdev;
    KEY_COMP a;
    KEY_COMP b;
    int tid;
    int is_dma;
    int is_interrupt;
    char str[30];
};

void *thread_func(void *arg)
{
    struct thread_struct *ts = (struct thread_struct *)arg;
    DEV_HANDLE cdev = ts->cdev;
    KEY_COMP a = ts->a, b = ts->b;
    int is_dma = ts->is_dma, is_interrupt = ts->is_interrupt;
    char * msg= (char*)(ts->str);
    int tid = ts->tid;
    uint64_t size = strlen(msg);
    char op_text[size + 3];
    strncpy(op_text, msg, size+1);

    cdev = create_handle();

    if (cdev == ERROR)
    {
        printf("Unable to create handle for device\n");
        exit(0);
    }

    if (set_key(cdev, a, b) == ERROR)
    {
        printf("Unable to set key\n");
        exit(0);
    }

    if (set_config(cdev, DMA, is_dma) == ERROR)
    {
        printf("Unable to set DMA\n");
        exit(0);
    }

    if (set_config(cdev, INTERRUPT, is_interrupt) == ERROR)
    {
        printf("Unable to set interrupt\n");
        exit(0);
    }
    printf("%d Original Text: %s\n", tid, msg);

    encrypt(cdev, op_text, size, 0);
    printf("%d Encrypted Text: %s\n", tid, op_text);

    decrypt(cdev, op_text, size, 0);
    printf("%d Decrypted Text: %s\n", tid, op_text);

    close_handle(cdev);
}

int main()
{
    DEV_HANDLE cdev;
    struct thread_struct tx[NUM_THREADS];
    char s1[30] = "Hello World 1324";
    char s2[30] = "nice asgnq34";
    char s3[30] = "Do you tt 24!!";
    char s4[30] = "is it that09??";
    for (int i = 0; i < NUM_THREADS; i++){
        tx[i].a = i + 4;
        tx[i].b = 2 * i + 5;
        tx[i].is_dma = (i & 1);
        tx[i].is_interrupt = (i & 2) >> 1;

        switch ((i*i)%4) {
            case 0:
            {
                strncpy(tx[i].str, s1, strlen(s1)+1); 
                break;
            }
            case 1:
            {   
                strncpy(tx[i].str, s2, strlen(s2)+1); 
                break;
            }
            case 2:
            {
                strncpy(tx[i].str, s3, strlen(s3)+1); 
                break;
            }
            case 3:
            {
                strncpy(tx[i].str, s4, strlen(s4)+1); 
                break;
            }
        }
        tx[i].tid = i;
    }
    pthread_t my_thread[NUM_THREADS];
    for(int i = 0; i<NUM_THREADS; i++){
        if(pthread_create(&my_thread[i], NULL, thread_func, &tx[i]) != 0){
            return -1;
        }
    }
    for(int i = 0; i<NUM_THREADS; i++){
        pthread_join(my_thread[i], NULL);
    }
    return 0;
}
