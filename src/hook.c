#include <asm/processor-flags.h>

#include "interface.h"
#include "mem_tracker.h"

static int command;
static unsigned long tlb_misses, readwss, writewss, unused;
static unsigned long start_ptr, end_ptr, total_pages;

struct vma_range_t {
    unsigned long vm_start;
    unsigned long vm_end;
};
static struct vma_range_t* vma_ranges;
static unsigned long size_during_open;

struct page_info_t {
    pte_t *pte;
    unsigned long tlb_misses;
    unsigned long readwss;
    unsigned long writewss;
    unsigned long unused;
};
static struct page_info_t *page_infos;

static ssize_t memtrack_command_show(struct kobject *kobj,
                                     struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%d\n", command);
}

static ssize_t memtrack_command_set(struct kobject *kobj,
                                    struct kobj_attribute *attr,
                                    const char *buf, size_t count) {
    char cmd;
    if (count == 0 || buf == NULL) {
        printk(KERN_WARNING "Either buffer is NULL or file is empty.\n");
        return count;
    }
    cmd = *((char*)buf);
    command = (int)(cmd - '0');
    if (command < 0 || command > 2) {
        printk(KERN_WARNING "Wrong command (%c) has been sent to memtrack module.\n", cmd);
    }
    return count;
}

static struct kobj_attribute memtrack_command_attribute =
    __ATTR(command, 0644, memtrack_command_show, memtrack_command_set);

static ssize_t memtrack_tlb_misses_show(struct kobject *kobj,
                                        struct kobj_attribute *attr,
                                        char *buf) {
    return sprintf(buf, "%lu\n", tlb_misses);
}

static struct kobj_attribute memtrack_tlb_misses_attribute =
    __ATTR(tlb_misses, 0444, memtrack_tlb_misses_show, NULL);

static ssize_t memtrack_readwss_show(struct kobject *kobj,
                                     struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%lu\n", readwss);
}

static struct kobj_attribute memtrack_readwss_attribute =
    __ATTR(readwss, 0444, memtrack_readwss_show, NULL);

static ssize_t memtrack_writewss_show(struct kobject *kobj,
                                      struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%lu\n", writewss);
}

static struct kobj_attribute memtrack_writewss_attribute =
    __ATTR(writewss, 0444, memtrack_writewss_show, NULL);

static ssize_t memtrack_unused_show(struct kobject *kobj,
                                    struct kobj_attribute *attr, char *buf) {
    return sprintf(buf, "%lu\n", unused);
}

static struct kobj_attribute memtrack_unused_attribute =
    __ATTR(unused, 0444, memtrack_unused_show, NULL);

static struct attribute *memtrack_attrs[] = {
    &memtrack_command_attribute.attr, &memtrack_tlb_misses_attribute.attr,
    &memtrack_readwss_attribute.attr, &memtrack_writewss_attribute.attr,
    &memtrack_unused_attribute.attr,  NULL,
};

struct attribute_group memtrack_attr_group = {
    .attrs = memtrack_attrs,
    .name = "memtrack",
};

static int fault_hook(struct mm_struct *mm, struct pt_regs *regs,
                      unsigned long error_code, unsigned long address) {
    unsigned long ind, cr3;
    volatile char temp;
    pte_t *pte;
    if (address >= start_ptr && address < end_ptr) {
        ind = (address - start_ptr) >> 12;
        page_infos[ind].tlb_misses += 1;
        tlb_misses += 1;
        // For command 2
        if (page_infos[ind].unused == 1) {
            page_infos[ind].unused = 0;
            unused -= 1;
        }
        if (error_code & (0x1UL << 1)) {
            // Write operation
            if (page_infos[ind].writewss == 0) {
                // First time write.
                if (page_infos[ind].readwss > 0) {
                    // A read was made before.
                    readwss -= 1;
                }
                writewss += 1;
            }
            page_infos[ind].writewss += 1;
        } else {
            // Read operation
            if (page_infos[ind].writewss == 0 && page_infos[ind].readwss == 0) {
                // First read access to page and no write before.
                readwss += 1;
            }
            page_infos[ind].readwss += 1;
        }
        pte = page_infos[ind].pte;
        pte->pte &= ~(0x1UL << 50);
        // Access the page table entry now so it is in the TLB.
        if (command == 1) {
            // PTI enabled. change the ASID to that of user.
            __asm__ __volatile__(
                    "mov %%cr3, %0;"
                    :"=r" (cr3)
                    :
                    :"memory"
                    );
            cr3 |= (1 << X86_CR3_PTI_PCID_USER_BIT);
            __asm__ __volatile__(
                    "mov %0, %%cr3;"
                    :
                    :"r" (cr3)
                    :"memory"
                    );
            temp = *((char*)address);
            *((char*)address) = temp;
            cr3 &= ~(1 << X86_CR3_PTI_PCID_USER_BIT);
            __asm__ __volatile__(
                    "mov %0, %%cr3;"
                    :
                    :"r" (cr3)
                    :"memory"
                    );
        } else if (command == 2) {
            __native_flush_tlb();
            if (error_code & (0x1UL << 1)) {
                // In case of a write, do write access
                // so that dirty bit is set.
                temp = *((char*)address);
                *((char*)address) = temp;
            } else {
                // In case of read do read access.
                temp = *((char*)address);
            }
        } else {
            // command is 0.
            // Do a read and then write with same value
            // so that dirty bit is set and we do not get wrong
            // miss count.
            temp = *((char*)address);
            *((char*)address) = temp;
        }
        // Repoison the page table entry
        pte->pte |= (0x1UL << 50);
        return 0;
    }
    return -1;
}

static pte_t* get_pte(unsigned long addr) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct mm_struct *mm = current->mm;
    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd))) {
        goto null_ret;
    }
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d))) {
        goto null_ret;
    }
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || unlikely(pud_bad(*pud))) {
        goto null_ret;
    }
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || unlikely(pmd_bad(*pmd)) || unlikely(pmd_trans_huge(*pmd))) {
        goto null_ret;
    }
    pte = pte_offset_map(pmd, addr);
    if (pte == NULL) {
        goto null_ret;
    }
    return pte;
null_ret:
    printk(KERN_WARNING "Could not transalte address and find pte.\n");
    return NULL;
}

static bool poison_page(unsigned long addr) {
    pte_t *pte = get_pte(addr);
    if (pte == NULL) {
        return false;
    }
    page_infos[(addr - start_ptr) >> 12].pte = pte;
    pte->pte |= (0x1UL << 50);
    if (command == 2) {
        // Flush the TLB only when counting read/writes
        __native_flush_tlb_one_user(addr);
        // Clear the dirty bit of the page only when counting read/writes
        pte->pte &= ~(0x1UL << 6);
    }
    return true;
}

static bool unpoison_page(unsigned long addr) {
    pte_t *pte = get_pte(addr);
    if (pte == NULL) {
        return false;
    }
    pte->pte &= ~(0x1UL << 50);
    return true;
}

ssize_t handle_read(char *buff, size_t length) {
    unsigned long ind, addr, count, vaddr, i;
    bool flag;
    struct page_info_t *page_info;
    struct read_command *cmd;
    cmd = (struct read_command*)buff;
    if (cmd->command == FAULT_START) {
        // Poison the page table entries.
        total_pages = (end_ptr - start_ptr) >> 12;
        page_infos = kmalloc(total_pages * sizeof(struct page_info_t), GFP_KERNEL);
        for (addr = start_ptr; addr < end_ptr; addr += (1 << 12)) {
            if (!poison_page(addr)) {
                printk(KERN_WARNING "Something went wrong in poisoning the pages.\n");
                return -1;
            }
            ind = (addr - start_ptr) >> 12;
            page_infos[ind].unused = 1;
            page_infos[ind].writewss = 0;
            page_infos[ind].readwss = 0;
            page_infos[ind].tlb_misses = 0;
        }
        tlb_misses = 0;
        readwss = 0, writewss = 0;
        unused = total_pages;
    } else {
        if (cmd->command >= MAX_READ_COMMANDS) {
            printk(KERN_WARNING "Unknown command sent to handle_read.\n");
            return -1;
        }
        for (ind = 0; ind < MAX_TOPPERS; ind++) {
            cmd->toppers[ind].vaddr = 0;
            cmd->toppers[ind].count = 0;
        }
        if (cmd->command == TLBMISS_TOPPERS) {
            cmd->valid_entries = min(total_pages, (unsigned long)MAX_TOPPERS);
        } else {
            cmd->valid_entries = 0;
            for (addr = start_ptr; addr < end_ptr; addr += (1 << 12)) {
                page_info = page_infos + ((addr - start_ptr) >> 12);
                if (cmd->command == READ_TOPPERS) {
                    if (page_info->readwss == 0 || page_info->writewss > 0) {
                        continue;
                    }
                } else {
                    if (page_info->writewss == 0) {
                        continue;
                    }
                }
                cmd->valid_entries += 1;
            }
            cmd->valid_entries = min(cmd->valid_entries, (long)MAX_TOPPERS);
        }
        for (ind = 0; ind < cmd->valid_entries; ind++) {
            count = 0;
            vaddr = 0;
            for (addr = start_ptr; addr < end_ptr; addr += (1 << 12)) {
                page_info = page_infos + ((addr - start_ptr) >> 12);
                if (cmd->command == READ_TOPPERS) {
                    if (page_info->readwss == 0 || page_info->writewss > 0) {
                        continue;
                    }
                } else if (cmd->command == WRITE_TOPPERS) {
                    if (page_info->writewss == 0) {
                        continue;
                    }
                }
                flag = false; // not present earlier
                for (i = 0; i < cmd->valid_entries; i++) {
                    if (cmd->toppers[i].vaddr == addr) {
                        flag = true;
                    }
                }
                if (flag) {
                    continue;
                }
                switch (cmd->command) {
                case TLBMISS_TOPPERS:
                    if (count <= page_info->tlb_misses) {
                        count = page_info->tlb_misses;
                        vaddr = addr;
                    }
                    break;
                case READ_TOPPERS:
                    if (count <= page_info->readwss) {
                        count = page_info->readwss;
                        vaddr = addr;
                    }
                    break;
                case WRITE_TOPPERS:
                    if (count <= page_info->writewss) {
                        count = page_info->writewss;
                        vaddr = addr;
                    }
                    break;
                default:
                    break;
                }
            }
            cmd->toppers[ind].vaddr = vaddr;
            cmd->toppers[ind].count = count;
        }
    }
    return 0;
}

static bool vma_ranges_contains(unsigned long addr) {
    int ind;
    for (ind = 0; ind < size_during_open; ind++) {
        if (vma_ranges[ind].vm_start <= addr && addr < vma_ranges[ind].vm_end) {
            return true;
        }
    }
    return false;
}

ssize_t handle_write(const char *buff, size_t lenth) {
    struct vm_area_struct *head, *trav;

    stac();
    start_ptr = *((unsigned long*)buff);
    clac();

    head = current->mm->mmap;
    trav = head;
    if (trav->vm_start > start_ptr || trav->vm_end <= start_ptr) {
        trav = trav->vm_next;
        while (trav != head && trav != NULL) {
            if (trav->vm_start <= start_ptr && trav->vm_end > start_ptr) {
                break;
            }
            trav = trav->vm_next;
        }
    }
    end_ptr = trav->vm_end;
    while (vma_ranges_contains(end_ptr - 1)) {
        end_ptr -= (1 << 12);
    }
    if (end_ptr <= start_ptr) {
        printk(KERN_WARNING "end_ptr is less than start_ptr.\n");
        return -1;
    }
    kfree(vma_ranges);

    return 8;
}

int handle_open(void) {
    unsigned long ind;
    struct vm_area_struct *head, *trav;

    head = current->mm->mmap;
    if (head == NULL) {
        printk(KERN_WARNING "No vm_area as of now.\n");
        return -1;
    }
    size_during_open = 1;
    trav = head->vm_next;
    while (trav != head && trav != NULL) {
        trav = trav->vm_next;
        size_during_open += 1;
    }
    vma_ranges = kmalloc(size_during_open * sizeof(struct vma_range_t), GFP_KERNEL);
    if (vma_ranges == NULL) {
        printk(KERN_WARNING "Failed to allocate memory for vma_ranges.\n");
        return -1;
    }
    trav = head;
    for (ind = 0; ind < size_during_open; ind++) {
        vma_ranges[ind].vm_start = trav->vm_start;
        vma_ranges[ind].vm_end = trav->vm_end;
        trav = trav->vm_next;
    }

    page_fault_pid = current->pid;
    rsvd_fault_hook = &fault_hook;
    return 0;
}

int handle_close(void) {
    unsigned long addr;

    page_fault_pid = -1;
    rsvd_fault_hook = NULL;

    // Unpoison the page table entries.
    for (addr = start_ptr; addr < end_ptr; addr += (1 << 12)) {
        if (!unpoison_page(addr)) {
            printk(KERN_WARNING "Something went wrong in unpoisoning the pages.\n");
            return -1;
        }
    }
    kfree(page_infos);
    return 0;
}
