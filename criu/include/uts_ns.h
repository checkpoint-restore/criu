#ifndef __CR_UTS_NS_H__
#define __CR_UTS_NS_H__

extern int dump_uts_ns(int ns_id);
extern int prepare_utsns(int ns_img_id, int real_pid);

extern struct ns_desc uts_ns_desc;

#endif /* __CR_UTS_NS_H__ */
