#ifndef __PROC_PARSE_H__
#define __PROC_PARSE_H__
int parse_maps(pid_t pid, int pid_dir, struct list_head *vma_area_list, bool use_map_files);
#endif
