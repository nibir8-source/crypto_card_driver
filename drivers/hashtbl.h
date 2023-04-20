#ifndef HASHTBL_H
#define HASHTBL_H

typedef unsigned char KEY_COMP;

struct proc_struct{
    KEY_COMP a;
    KEY_COMP b;
    int is_dma;
    int is_interrupt;
    int key_set_flag;
};

struct hash_node {
    int pid;
    struct proc_struct* data;
    struct hash_node * next;
};

#define BUCKETS 1024

inline int myhash(int pid);
struct proc_struct * find(struct hash_node**, int pid);
void insert(struct hash_node** hash_tbl, int pid, struct proc_struct * pz);

#endif
