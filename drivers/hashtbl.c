#include<linux/mm.h>
#include "hashtbl.h"

inline int myhash(int pid){
    return pid & (BUCKETS - 1);
}

struct proc_struct* find(struct hash_node** hash_tbl, int pid){
    int key;
    struct hash_node *cur;

    key = myhash(pid);
    cur = hash_tbl[key];
    if(cur == NULL){
        return NULL;
    }
    while(cur != NULL){
        if(cur->pid == pid){
            return cur->data;
        }
        else{
            cur = cur->next;
        }
    }
    return NULL;
}

void insert(struct hash_node** hash_tbl, int pid, struct proc_struct * pz){
    int key;
    struct hash_node * node;

    key = myhash(pid);
    node = (struct hash_node *)kzalloc(sizeof(struct hash_node), GFP_KERNEL);
    node->data = pz;
    node->pid = pid;
    node->next = hash_tbl[key];
    hash_tbl[key] = node;
    return;
}
