#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/slab.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/fs_struct.h>
#include <asm/tlbflush.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/io.h>
#include <linux/semaphore.h>
#include <linux/dma-mapping.h>
#include <uapi/asm-generic/mman-common.h>

//UTILITY FUNCTIONS 
pte_t* Page_table_walker(struct mm_struct * mm, unsigned long addr){

    // taken from https://stackoverflow.com/questions/8980193/walking-page-tables-of-a-process-in-linux
	pgd_t*pgd;
	p4d_t* p4d;
	pud_t* pud;
	pmd_t * pmd;
	pte_t * ptep;
	pte_t pte;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd)){
    printk("Invalid pgd");
    return NULL;
	}

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d)){
		printk("Invalid p4d");
		return NULL;
	}

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud)){
		printk("Invalid pud");
		return NULL;
	}

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd) || pmd_bad(*pmd)){
		printk("Invalid pmd");
		return NULL;
	}


	ptep = pte_offset_map(pmd, addr);
	if (!ptep){
		printk("Invalid ptep");
		return NULL;
	}

	pte = *ptep;
	if (pte_present(pte)){
		return ptep;
	}	
	return NULL;
}
