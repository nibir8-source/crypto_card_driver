#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <crypter.h>
#include <pthread.h>

struct thread_struct{
  DEV_HANDLE cdev;
  KEY_COMP a;
  KEY_COMP b;
  int tid;
  int is_dma;
  int is_interrupt;
  char *str;
};

void* thread_function(void* arg)
{
  struct thread_struct *ts = (struct thread_struct *)arg;
  DEV_HANDLE cdev = ts->cdev;
  KEY_COMP a = ts->a, b = ts->b;
  int is_dma = ts->is_dma, is_interrupt = ts->is_interrupt;
  char *msg = ts->str;
  int tid = ts->tid;
  uint64_t size = strlen(msg);
  char op_text[size + 3];
  strcpy(op_text, msg);

  cdev = create_handle();

  if(cdev == ERROR)
  {
    printf("Unable to create handle for device\n");
    exit(0);
  }

  if(set_key(cdev, a, b) == ERROR){
    printf("Unable to set key\n");
    exit(0);
  }

  if(set_config(cdev, DMA, is_dma) == ERROR){
      printf("Unable to set DMA\n");
      exit(0);
  }

  if(set_config(cdev, INTERRUPT, is_interrupt) == ERROR){
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
  struct thread_struct t1, t2, t3;
  t1.a = 2, t1.b = 23; t1.is_dma = 0, t1.is_interrupt = 1;
  t2.a = 56, t2.b = 34; t2.is_dma = 1, t2.is_interrupt = 0;
  t3.a = 9, t3.b = 89; t3.is_dma = 1, t3.is_interrupt = 1;
  t1.str = "Hello CS730!";
  t2.str = "Adit, Ashwani multicore kar le bc!";
  t3.str = "Party jaldi de do!";
  t1.tid = 0;
  t2.tid = 1;
  t3.tid = 2;

  pthread_t my_thread[3];

  if(pthread_create(&my_thread[0], NULL, thread_function, &t1) != 0) {
    perror("pthread_create 1");
    return 1;
  }

  if(pthread_create(&my_thread[1], NULL, thread_function, &t2) != 0) {
    perror("pthread_create 2");
    return 1;
  }

  if(pthread_create(&my_thread[2], NULL, thread_function, &t3) != 0) {
    perror("pthread_create 3");
    return 1;
  }
  
  pthread_join(my_thread[0], NULL);
  pthread_join(my_thread[1], NULL);
  pthread_join(my_thread[2], NULL);

  return 0;
}
