#ifndef __CR_SUD_H__
#define __CR_SUD_H__

/*
 * These macros mirror PR_SYS_DISPATCH_* from <linux/prctl.h>
 */
#ifndef SYS_DISPATCH_OFF
#define SYS_DISPATCH_OFF 0
#endif

#ifndef SYS_DISPATCH_ON
#define SYS_DISPATCH_ON 1
#endif

struct sys_dispatch_entry {
	struct rb_node node;
    struct sys_dispatch_entry *next;
    pid_t tid_real;
    unsigned mode;

    /* Index of SysDispatchSetting in dumped img, if mode == on */
    size_t img_setting_pos;
    /* Per-tid SUD settings, if mode == on */
    unsigned long selector;
    unsigned long offset;
    unsigned long len;
};

extern struct sys_dispatch_entry *sud_lookup(pid_t tid_real, bool create, bool mandatory);
#define sud_find_entry(tid_real) sud_lookup(tid_real, false, true)
extern int sud_collect_entry(pid_t tid_real);
extern int sud_read_image(void);
extern int restore_sud_per_core(pid_t tid_real);
extern int dump_sud_per_core(pid_t tid_real, ThreadCoreEntry *tc);
extern int dump_sud(void);


#endif