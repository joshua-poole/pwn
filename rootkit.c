#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

static int __init mod_init(void) {
    prink(KERN_INFO "rootkit: init\n");

    return 0;
}

static void __exit mod_exit(void) {
    prink(KERN_INFO "rootkit: exit\n");
}

module_init(mod_init);
module_exit(mod_exit);