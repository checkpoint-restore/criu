
[root@localhost criu]# git status
位于分支 criu-mips
尚未暂存以备提交的变更：
  （使用 "git add <file>..." 更新要提交的内容）
  （使用 "git checkout -- <file>..." 丢弃工作区的改动）

	修改：     Makefile
	修改：     compel/include/uapi/handle-elf.h
	修改：     compel/plugins/Makefile
	修改：     compel/src/lib/handle-elf.c
	修改：     compel/src/lib/infect.c
	修改：     compel/src/main.c
	修改：     criu/cr-restore.c
	修改：     criu/pie/Makefile
	修改：     criu/pie/Makefile.library
	修改：     criu/pie/restorer.c
	修改：     images/Makefile
	修改：     images/core.proto
	修改：     images/sa.proto

未跟踪的文件:
  （使用 "git add <file>..." 以包含要提交的内容）

	compel/arch/mips/
	criu/arch/mips/
	images/core-mips.proto
	include/common/arch/mips/

修改尚未加入提交（使用 "git add" 和/或 "git commit -a"）
[root@localhost criu]# meld ./criu/include/image.h ../gysun/criu-my/./criu/include/image.h
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)

(meld:18568): dconf-WARNING **: 10:18:16.400: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.400: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.401: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.401: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.404: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.404: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.404: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.404: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.407: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.407: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.407: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.407: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.617: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.618: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.619: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:16.619: failed to commit changes to dconf: 连接已关闭

(meld:18568): dconf-WARNING **: 10:18:18.495: failed to commit changes to dconf: 连接已关闭

(meld:18568): Gtk-CRITICAL **: 10:18:27.886: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18568): Gtk-CRITICAL **: 10:18:27.886: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18568): Gtk-CRITICAL **: 10:18:27.886: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18568): Gtk-CRITICAL **: 10:18:27.886: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18568): Gtk-CRITICAL **: 10:18:27.887: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18568): Gtk-CRITICAL **: 10:18:27.887: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18568): Gtk-CRITICAL **: 10:18:27.887: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18568): Gtk-CRITICAL **: 10:18:27.887: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18568): Gtk-CRITICAL **: 10:18:27.887: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed
[root@localhost criu]# meld ./criu/parasite-syscall.c ../gysun/criu-my/./criu/parasite-syscall.c
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)

(meld:18646): dconf-WARNING **: 10:18:47.575: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.575: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.575: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.575: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.578: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.578: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.578: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.578: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.581: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.581: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.581: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.581: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.774: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.774: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.775: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:47.785: failed to commit changes to dconf: 连接已关闭

(meld:18646): dconf-WARNING **: 10:18:49.317: failed to commit changes to dconf: 连接已关闭

(meld:18646): Gtk-CRITICAL **: 10:19:37.986: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18646): Gtk-CRITICAL **: 10:19:37.986: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18646): Gtk-CRITICAL **: 10:19:37.986: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18646): Gtk-CRITICAL **: 10:19:37.986: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18646): Gtk-CRITICAL **: 10:19:37.987: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18646): Gtk-CRITICAL **: 10:19:37.987: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18646): Gtk-CRITICAL **: 10:19:37.987: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18646): Gtk-CRITICAL **: 10:19:37.987: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18646): Gtk-CRITICAL **: 10:19:37.987: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed
[root@localhost criu]# meld ./criu/pie/parasite.c ../gysun/criu-my/./criu/pie/parasite.c
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)

(meld:18784): dconf-WARNING **: 10:19:54.197: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.197: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.197: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.197: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.199: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.199: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.200: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.200: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.202: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.202: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.202: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.203: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.394: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.394: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.395: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:54.395: failed to commit changes to dconf: 连接已关闭

(meld:18784): dconf-WARNING **: 10:19:56.165: failed to commit changes to dconf: 连接已关闭

(meld:18784): Gtk-CRITICAL **: 10:20:29.865: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18784): Gtk-CRITICAL **: 10:20:29.866: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18784): Gtk-CRITICAL **: 10:20:29.866: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18784): Gtk-CRITICAL **: 10:20:29.866: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18784): Gtk-CRITICAL **: 10:20:29.866: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18784): Gtk-CRITICAL **: 10:20:29.866: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18784): Gtk-CRITICAL **: 10:20:29.867: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18784): Gtk-CRITICAL **: 10:20:29.867: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18784): Gtk-CRITICAL **: 10:20:29.867: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed
[root@localhost criu]# meld ./criu/pie/restorer.c ../gysun/criu-my/./criu/pie/restorer.c
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)

(meld:18941): dconf-WARNING **: 10:20:44.945: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.946: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.946: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.946: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.948: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.948: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.948: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.949: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.951: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.951: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.951: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:44.951: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:45.150: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:45.150: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:45.151: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:45.151: failed to commit changes to dconf: 连接已关闭

(meld:18941): dconf-WARNING **: 10:20:46.859: failed to commit changes to dconf: 连接已关闭

(meld:18941): Gtk-CRITICAL **: 10:21:24.375: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18941): Gtk-CRITICAL **: 10:21:24.375: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18941): Gtk-CRITICAL **: 10:21:24.375: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18941): Gtk-CRITICAL **: 10:21:24.375: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18941): Gtk-CRITICAL **: 10:21:24.376: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18941): Gtk-CRITICAL **: 10:21:24.376: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18941): Gtk-CRITICAL **: 10:21:24.376: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18941): Gtk-CRITICAL **: 10:21:24.376: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:18941): Gtk-CRITICAL **: 10:21:24.376: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed
[root@localhost criu]# meld ./criu/proc_parse.c ../gysun/criu-my/./criu/proc_parse.c
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)

(meld:19103): dconf-WARNING **: 10:21:39.477: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.477: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.477: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.477: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.480: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.480: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.480: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.480: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.482: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.483: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.483: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.483: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.694: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.695: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.699: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:39.699: failed to commit changes to dconf: 连接已关闭

(meld:19103): dconf-WARNING **: 10:21:41.138: failed to commit changes to dconf: 连接已关闭

(meld:19103): Gtk-CRITICAL **: 10:22:14.112: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19103): Gtk-CRITICAL **: 10:22:14.112: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19103): Gtk-CRITICAL **: 10:22:14.112: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19103): Gtk-CRITICAL **: 10:22:14.113: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19103): Gtk-CRITICAL **: 10:22:14.113: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19103): Gtk-CRITICAL **: 10:22:14.113: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19103): Gtk-CRITICAL **: 10:22:14.113: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19103): Gtk-CRITICAL **: 10:22:14.113: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19103): Gtk-CRITICAL **: 10:22:14.113: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed
[root@localhost criu]# meld ./criu/cr-restore.c ../gysun/criu-my/./criu/cr-restore.c
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)

(meld:19275): dconf-WARNING **: 10:22:42.139: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.140: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.140: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.140: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.143: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.143: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.143: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.143: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.146: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.146: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.146: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.146: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.338: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.338: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.339: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:42.339: failed to commit changes to dconf: 连接已关闭

(meld:19275): dconf-WARNING **: 10:22:47.686: failed to commit changes to dconf: 连接已关闭

(meld:19275): Gtk-CRITICAL **: 10:23:06.667: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19275): Gtk-CRITICAL **: 10:23:06.667: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19275): Gtk-CRITICAL **: 10:23:06.667: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19275): Gtk-CRITICAL **: 10:23:06.667: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19275): Gtk-CRITICAL **: 10:23:06.668: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19275): Gtk-CRITICAL **: 10:23:06.668: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19275): Gtk-CRITICAL **: 10:23:06.668: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19275): Gtk-CRITICAL **: 10:23:06.668: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:19275): Gtk-CRITICAL **: 10:23:06.668: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed
[root@localhost criu]# make clean;make
  CLEAN    Documentation
  CLEAN    test/compel
  CLEAN    images
  CLEAN    criu/arch/mips
  CLEAN    criu/pie
  CLEAN    criu
  CLEAN    criu/pie
  CLEAN    criu
  CLEAN    soccr
  CLEAN    lib/c
  CLEAN    lib/py/images
  CLEAN    lib/py
  CLEAN    lib
  CLEAN    compel
  CLEAN    compel/plugins
  CLEAN    lib/c
  CLEAN    lib/py/images
  CLEAN    lib/py
  CLEAN    lib
  CLEAN    crit
Note: Building without GnuTLS support
  GEN      .gitid
  GEN      criu/include/version.h
  GEN      include/common/asm
  PBCC     images/remote-image.pb-c.c
  DEP      images/remote-image.pb-c.d
  PBCC     images/google/protobuf/descriptor.pb-c.c
  PBCC     images/opts.pb-c.c
  PBCC     images/sit.pb-c.c
  DEP      images/google/protobuf/descriptor.pb-c.d
  DEP      images/opts.pb-c.d
  DEP      images/sit.pb-c.d
  PBCC     images/macvlan.pb-c.c
  DEP      images/macvlan.pb-c.d
  PBCC     images/autofs.pb-c.c
  DEP      images/autofs.pb-c.d
  PBCC     images/sysctl.pb-c.c
  DEP      images/sysctl.pb-c.d
  PBCC     images/time.pb-c.c
  DEP      images/time.pb-c.d
  PBCC     images/binfmt-misc.pb-c.c
  DEP      images/binfmt-misc.pb-c.d
  PBCC     images/seccomp.pb-c.c
  DEP      images/seccomp.pb-c.d
  PBCC     images/userns.pb-c.c
  DEP      images/userns.pb-c.d
  PBCC     images/cgroup.pb-c.c
  DEP      images/cgroup.pb-c.d
  PBCC     images/fown.pb-c.c
  PBCC     images/ext-file.pb-c.c
  DEP      images/fown.pb-c.d
  DEP      images/ext-file.pb-c.d
  PBCC     images/rpc.pb-c.c
  DEP      images/rpc.pb-c.d
  PBCC     images/siginfo.pb-c.c
  DEP      images/siginfo.pb-c.d
  PBCC     images/pagemap.pb-c.c
  DEP      images/pagemap.pb-c.d
  PBCC     images/rlimit.pb-c.c
  DEP      images/rlimit.pb-c.d
  PBCC     images/file-lock.pb-c.c
  DEP      images/file-lock.pb-c.d
  PBCC     images/tty.pb-c.c
  DEP      images/tty.pb-c.d
  PBCC     images/tun.pb-c.c
  PBCC     images/netdev.pb-c.c
  DEP      images/tun.pb-c.d
  DEP      images/netdev.pb-c.d
  PBCC     images/vma.pb-c.c
  DEP      images/vma.pb-c.d
  PBCC     images/creds.pb-c.c
  DEP      images/creds.pb-c.d
  PBCC     images/utsns.pb-c.c
  DEP      images/utsns.pb-c.d
  PBCC     images/ipc-desc.pb-c.c
  PBCC     images/ipc-sem.pb-c.c
  DEP      images/ipc-desc.pb-c.d
  DEP      images/ipc-sem.pb-c.d
  PBCC     images/ipc-msg.pb-c.c
  DEP      images/ipc-msg.pb-c.d
  PBCC     images/ipc-shm.pb-c.c
  DEP      images/ipc-shm.pb-c.d
  PBCC     images/ipc-var.pb-c.c
  DEP      images/ipc-var.pb-c.d
  PBCC     images/sk-opts.pb-c.c
  PBCC     images/packet-sock.pb-c.c
  DEP      images/sk-opts.pb-c.d
  DEP      images/packet-sock.pb-c.d
  PBCC     images/sk-netlink.pb-c.c
  DEP      images/sk-netlink.pb-c.d
  PBCC     images/sk-inet.pb-c.c
  DEP      images/sk-inet.pb-c.d
  PBCC     images/sk-unix.pb-c.c
  DEP      images/sk-unix.pb-c.d
  PBCC     images/mm.pb-c.c
  DEP      images/mm.pb-c.d
  PBCC     images/timerfd.pb-c.c
  DEP      images/timerfd.pb-c.d
  PBCC     images/timer.pb-c.c
  DEP      images/timer.pb-c.d
  PBCC     images/sa.pb-c.c
  DEP      images/sa.pb-c.d
  PBCC     images/pipe-data.pb-c.c
  DEP      images/pipe-data.pb-c.d
  PBCC     images/mnt.pb-c.c
  DEP      images/mnt.pb-c.d
  PBCC     images/sk-packet.pb-c.c
  DEP      images/sk-packet.pb-c.d
  PBCC     images/tcp-stream.pb-c.c
  DEP      images/tcp-stream.pb-c.d
  PBCC     images/pipe.pb-c.c
  DEP      images/pipe.pb-c.d
  PBCC     images/pstree.pb-c.c
  DEP      images/pstree.pb-c.d
  PBCC     images/fs.pb-c.c
  DEP      images/fs.pb-c.d
  PBCC     images/signalfd.pb-c.c
  DEP      images/signalfd.pb-c.d
  PBCC     images/fh.pb-c.c
  PBCC     images/fsnotify.pb-c.c
  DEP      images/fh.pb-c.d
  DEP      images/fsnotify.pb-c.d
  PBCC     images/eventpoll.pb-c.c
  DEP      images/eventpoll.pb-c.d
  PBCC     images/eventfd.pb-c.c
  DEP      images/eventfd.pb-c.d
  PBCC     images/remap-file-path.pb-c.c
  DEP      images/remap-file-path.pb-c.d
  PBCC     images/fifo.pb-c.c
  DEP      images/fifo.pb-c.d
  PBCC     images/ghost-file.pb-c.c
  DEP      images/ghost-file.pb-c.d
  PBCC     images/regfile.pb-c.c
  DEP      images/regfile.pb-c.d
  PBCC     images/ns.pb-c.c
  DEP      images/ns.pb-c.d
  PBCC     images/fdinfo.pb-c.c
  DEP      images/fdinfo.pb-c.d
  PBCC     images/core-aarch64.pb-c.c
  PBCC     images/core-arm.pb-c.c
  PBCC     images/core-mips.pb-c.c
  PBCC     images/core-ppc64.pb-c.c
  PBCC     images/core-s390.pb-c.c
  PBCC     images/core-x86.pb-c.c
  PBCC     images/core.pb-c.c
  PBCC     images/inventory.pb-c.c
  DEP      images/core-aarch64.pb-c.d
  DEP      images/core-arm.pb-c.d
  DEP      images/core-mips.pb-c.d
  DEP      images/core-ppc64.pb-c.d
  DEP      images/core-s390.pb-c.d
  DEP      images/core-x86.pb-c.d
  DEP      images/core.pb-c.d
  DEP      images/inventory.pb-c.d
  PBCC     images/cpuinfo.pb-c.c
  DEP      images/cpuinfo.pb-c.d
  PBCC     images/stats.pb-c.c
  DEP      images/stats.pb-c.d
make[1]: Nothing to be done for 'all'.
  CC       images/stats.o
  CC       images/core.o
  CC       images/core-x86.o
  CC       images/core-mips.o
  CC       images/core-arm.o
  CC       images/core-aarch64.o
  CC       images/core-ppc64.o
  CC       images/core-s390.o
  CC       images/cpuinfo.o
  CC       images/inventory.o
  CC       images/fdinfo.o
  CC       images/fown.o
  CC       images/ns.o
  CC       images/regfile.o
  CC       images/ghost-file.o
  CC       images/fifo.o
  CC       images/remap-file-path.o
  CC       images/eventfd.o
  CC       images/eventpoll.o
  CC       images/fh.o
  CC       images/fsnotify.o
  CC       images/signalfd.o
  CC       images/fs.o
  CC       images/pstree.o
  CC       images/pipe.o
  CC       images/tcp-stream.o
  CC       images/sk-packet.o
  CC       images/mnt.o
  CC       images/pipe-data.o
  CC       images/sa.o
  CC       images/timer.o
  CC       images/timerfd.o
  CC       images/mm.o
  CC       images/sk-opts.o
  CC       images/sk-unix.o
  CC       images/sk-inet.o
  CC       images/tun.o
  CC       images/sk-netlink.o
  CC       images/packet-sock.o
  CC       images/ipc-var.o
  CC       images/ipc-desc.o
  CC       images/ipc-shm.o
  CC       images/ipc-msg.o
  CC       images/ipc-sem.o
  CC       images/utsns.o
  CC       images/creds.o
  CC       images/vma.o
  CC       images/netdev.o
  CC       images/tty.o
  CC       images/file-lock.o
  CC       images/rlimit.o
  CC       images/pagemap.o
  CC       images/siginfo.o
  CC       images/rpc.o
  CC       images/ext-file.o
  CC       images/cgroup.o
  CC       images/userns.o
  CC       images/google/protobuf/descriptor.o
  CC       images/opts.o
  CC       images/seccomp.o
  CC       images/binfmt-misc.o
  CC       images/time.o
  CC       images/sysctl.o
  CC       images/autofs.o
  CC       images/macvlan.o
  CC       images/sit.o
  CC       images/remote-image.o
  LINK     images/built-in.o
  GEN      compel/include/asm
  GEN      compel/include/version.h
touch .config
  GEN      include/common/config.h
  GEN      compel/plugins/include/uapi/std/syscall-codes-64.h
  GEN      compel/plugins/include/uapi/std/syscall-64.h
  GEN      compel/arch/mips/plugins/std/syscalls-64.S
  DEP      compel/arch/mips/plugins/std/syscalls-64.d
  DEP      compel/arch/mips/plugins/std/memcpy.d
  DEP      compel/arch/mips/plugins/std/parasite-head.d
  GEN      compel/plugins/include/uapi/std/syscall.h
  GEN      compel/arch/mips/plugins/std/sys-exec-tbl-64.c
  GEN      compel/plugins/include/uapi/std/syscall-codes.h
  GEN      compel/plugins/include/uapi/std/asm/syscall-types.h
  DEP      compel/plugins/std/infect.d
  DEP      compel/plugins/std/string.d
  DEP      compel/plugins/std/log.d
  DEP      compel/plugins/std/fds.d
  DEP      compel/plugins/std/std.d
  DEP      compel/plugins/shmem/shmem.d
  DEP      compel/plugins/fds/fds.d
  CC       compel/plugins/std/std.o
  CC       compel/plugins/std/fds.o
  CC       compel/plugins/std/log.o
  CC       compel/plugins/std/string.o
  CC       compel/plugins/std/infect.o
  CC       compel/arch/mips/plugins/std/parasite-head.o
  CC       compel/arch/mips/plugins/std/memcpy.o
  CC       compel/arch/mips/plugins/std/syscalls-64.o
  AR       compel/plugins/std.lib.a
  CC       compel/plugins/fds/fds.o
  AR       compel/plugins/fds.lib.a
  HOSTDEP  compel/src/lib/log-host.d
  HOSTDEP  compel/src/lib/handle-elf-host.d
compel/src/lib/handle-elf-host.c:22:48: 致命错误：arch/mips/src/lib/include/ldsodefs.h：没有那个文件或目录
 #include "arch/mips/src/lib/include/ldsodefs.h"
                                                ^
编译中断。
  HOSTDEP  compel/arch/mips/src/lib/handle-elf-host.d
  HOSTDEP  compel/src/main-host.d
  DEP      compel/src/lib/ptrace.d
  DEP      compel/src/lib/infect.d
  DEP      compel/src/lib/infect-util.d
  DEP      compel/src/lib/infect-rpc.d
  DEP      compel/arch/mips/src/lib/infect.d
  DEP      compel/arch/mips/src/lib/cpu.d
  DEP      compel/src/lib/log.d
  DEP      compel/src/main.d
  DEP      compel/src/lib/handle-elf.d
compel/src/lib/handle-elf.c:22:48: 致命错误：arch/mips/src/lib/include/ldsodefs.h：没有那个文件或目录
 #include "arch/mips/src/lib/include/ldsodefs.h"
                                                ^
编译中断。
  DEP      compel/arch/mips/src/lib/handle-elf.d
  HOSTDEP  compel/src/lib/handle-elf-host.d
compel/src/lib/handle-elf-host.c:22:48: 致命错误：arch/mips/src/lib/include/ldsodefs.h：没有那个文件或目录
 #include "arch/mips/src/lib/include/ldsodefs.h"
                                                ^
编译中断。
  DEP      compel/src/lib/handle-elf.d
compel/src/lib/handle-elf.c:22:48: 致命错误：arch/mips/src/lib/include/ldsodefs.h：没有那个文件或目录
 #include "arch/mips/src/lib/include/ldsodefs.h"
                                                ^
编译中断。
  CC       compel/src/lib/log.o
  CC       compel/arch/mips/src/lib/cpu.o
  CC       compel/arch/mips/src/lib/infect.o
compel/arch/mips/src/lib/infect.c:61:5: 错误：与‘get_task_regs’类型冲突
 int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
     ^
In file included from compel/arch/mips/src/lib/infect.c:20:0:
compel/include/infect-priv.h:61:12: 附注：‘get_task_regs’的上一个声明在此
 extern int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
            ^
/opt/criu/scripts/nmk/scripts/build.mk:214: recipe for target 'compel/arch/mips/src/lib/infect.o' failed
make[1]: *** [compel/arch/mips/src/lib/infect.o] Error 1
Makefile.compel:35: recipe for target 'compel/libcompel.a' failed
make: *** [compel/libcompel.a] Error 2
[root@localhost criu]# meld compel/Makefile ../gysun/criu-my/Makefile
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)
Error creating proxy: 连接已关闭 (g-io-error-quark, 18)

(meld:22446): dconf-WARNING **: 10:24:39.094: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.094: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.094: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.094: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.097: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.097: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.097: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.097: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.100: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.100: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.100: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.100: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.299: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.299: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.301: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:39.301: failed to commit changes to dconf: 连接已关闭

(meld:22446): dconf-WARNING **: 10:24:41.083: failed to commit changes to dconf: 连接已关闭

(meld:22446): Gtk-CRITICAL **: 10:25:01.512: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:22446): Gtk-CRITICAL **: 10:25:01.512: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:22446): Gtk-CRITICAL **: 10:25:01.512: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:22446): Gtk-CRITICAL **: 10:25:01.513: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:22446): Gtk-CRITICAL **: 10:25:01.513: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:22446): Gtk-CRITICAL **: 10:25:01.513: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:22446): Gtk-CRITICAL **: 10:25:01.513: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:22446): Gtk-CRITICAL **: 10:25:01.513: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed

(meld:22446): Gtk-CRITICAL **: 10:25:01.513: gtk_container_foreach: assertion 'GTK_IS_CONTAINER (container)' failed
[root@localhost criu]# make
Note: Building without GnuTLS support
make[1]: Nothing to be done for 'all'.
make[1]: 'images/built-in.o' is up to date.
make[1]: 'compel/plugins/std.lib.a' is up to date.
make[1]: 'compel/plugins/fds.lib.a' is up to date.
  HOSTDEP  compel/src/lib/handle-elf-host.d
compel/src/lib/handle-elf-host.c:22:48: 致命错误：arch/mips/src/lib/include/ldsodefs.h：没有那个文件或目录
 #include "arch/mips/src/lib/include/ldsodefs.h"
                                                ^
编译中断。
  DEP      compel/src/lib/handle-elf.d
compel/src/lib/handle-elf.c:22:48: 致命错误：arch/mips/src/lib/include/ldsodefs.h：没有那个文件或目录
 #include "arch/mips/src/lib/include/ldsodefs.h"
                                                ^
编译中断。
  CC       compel/arch/mips/src/lib/infect.o
compel/arch/mips/src/lib/infect.c:61:5: 错误：与‘get_task_regs’类型冲突
 int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
     ^
In file included from compel/arch/mips/src/lib/infect.c:20:0:
compel/include/infect-priv.h:61:12: 附注：‘get_task_regs’的上一个声明在此
 extern int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
            ^
/opt/criu/scripts/nmk/scripts/build.mk:214: recipe for target 'compel/arch/mips/src/lib/infect.o' failed
make[1]: *** [compel/arch/mips/src/lib/infect.o] Error 1
Makefile.compel:35: recipe for target 'compel/libcompel.a' failed
make: *** [compel/libcompel.a] Error 2
[root@localhost criu]# make
Note: Building without GnuTLS support
make[1]: Nothing to be done for 'all'.
make[1]: 'images/built-in.o' is up to date.
make[1]: 'compel/plugins/std.lib.a' is up to date.
make[1]: 'compel/plugins/fds.lib.a' is up to date.
  HOSTDEP  compel/src/lib/log-host.d
  HOSTDEP  compel/src/lib/handle-elf-host.d
  HOSTDEP  compel/arch/mips/src/lib/handle-elf-host.d
  HOSTDEP  compel/src/main-host.d
  DEP      compel/src/lib/ptrace.d
  DEP      compel/src/lib/infect.d
  DEP      compel/src/lib/infect-util.d
  DEP      compel/src/lib/infect-rpc.d
  DEP      compel/arch/mips/src/lib/infect.d
  DEP      compel/arch/mips/src/lib/cpu.d
  DEP      compel/src/lib/log.d
  DEP      compel/src/main.d
  DEP      compel/src/lib/handle-elf.d
  DEP      compel/arch/mips/src/lib/handle-elf.d
  CC       compel/src/lib/log.o
  CC       compel/arch/mips/src/lib/cpu.o
  CC       compel/arch/mips/src/lib/infect.o
compel/arch/mips/src/lib/infect.c:61:5: 错误：与‘get_task_regs’类型冲突
 int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
     ^
In file included from compel/arch/mips/src/lib/infect.c:20:0:
compel/include/infect-priv.h:61:12: 附注：‘get_task_regs’的上一个声明在此
 extern int get_task_regs(pid_t pid, user_regs_struct_t *regs, save_regs_t save,
            ^
/opt/criu/scripts/nmk/scripts/build.mk:214: recipe for target 'compel/arch/mips/src/lib/infect.o' failed
make[1]: *** [compel/arch/mips/src/lib/infect.o] Error 1
Makefile.compel:35: recipe for target 'compel/libcompel.a' failed
make: *** [compel/libcompel.a] Error 2
[root@localhost criu]# make
Note: Building without GnuTLS support
make[1]: Nothing to be done for 'all'.
make[1]: 'images/built-in.o' is up to date.
make[1]: 'compel/plugins/std.lib.a' is up to date.
make[1]: 'compel/plugins/fds.lib.a' is up to date.
  DEP      compel/arch/mips/src/lib/infect.d
  CC       compel/arch/mips/src/lib/infect.o
  CC       compel/src/lib/infect-rpc.o
  CC       compel/src/lib/infect-util.o
  CC       compel/src/lib/infect.o
  CC       compel/src/lib/ptrace.o
  AR       compel/libcompel.a
  HOSTCC   compel/src/main-host.o
  HOSTCC   compel/arch/mips/src/lib/handle-elf-host.o
  HOSTCC   compel/src/lib/handle-elf-host.o
  HOSTCC   compel/src/lib/log-host.o
  HOSTLINK compel/compel-host-bin
compel/src/main-host.o：在函数‘piegen’中：
/opt/criu/compel/src/main-host.c:73：对‘opts’未定义的引用
/opt/criu/compel/src/main-host.c:75：对‘opts’未定义的引用
/opt/criu/compel/src/main-host.c:80：对‘opts’未定义的引用
/opt/criu/compel/src/main-host.c:84：对‘opts’未定义的引用
/opt/criu/compel/src/main-host.c:84：对‘opts’未定义的引用
compel/src/main-host.o:/opt/criu/compel/src/main-host.c:85: more undefined references to `opts' follow
collect2: 错误：ld 返回 1
/opt/criu/scripts/nmk/scripts/build.mk:243: recipe for target 'compel/compel-host-bin' failed
make[1]: *** [compel/compel-host-bin] Error 1
Makefile.compel:35: recipe for target 'compel/compel-host-bin' failed
make: *** [compel/compel-host-bin] Error 2
[root@localhost criu]# make
Note: Building without GnuTLS support
make[1]: Nothing to be done for 'all'.
make[1]: 'images/built-in.o' is up to date.
make[1]: 'compel/plugins/std.lib.a' is up to date.
make[1]: 'compel/plugins/fds.lib.a' is up to date.
  HOSTDEP  compel/src/main-host.d
  DEP      compel/src/main.d
make[1]: 'compel/libcompel.a' is up to date.
  HOSTCC   compel/src/main-host.o
  HOSTLINK compel/compel-host-bin
  DEP      soccr/soccr.d
  CC       soccr/soccr.o
  AR       soccr/libsoccr.a
make[1]: 'soccr/libsoccr.a' is up to date.
  DEP      criu/arch/mips/sigframe.d
  DEP      criu/arch/mips/crtools.d
  DEP      criu/arch/mips/cpu.d
  DEP      criu/arch/mips/bitops.d
  CC       criu/arch/mips/bitops.o
  CC       criu/arch/mips/cpu.o
  CC       criu/arch/mips/crtools.o
In file included from criu/include/kerndat.h:7:0,
                 from criu/arch/mips/crtools.c:26:
criu/arch/mips/include/asm/kerndat.h:5:0: 错误：“kdat_can_map_vdso”重定义 [-Werror]
 #define kdat_can_map_vdso()   0
 ^
In file included from criu/arch/mips/crtools.c:15:0:
criu/arch/mips/include/asm/restorer.h:73:0: 附注：这是先前定义的位置
 #define kdat_can_map_vdso(void)   0
 ^
cc1: all warnings being treated as errors
/opt/criu/scripts/nmk/scripts/build.mk:118: recipe for target 'criu/arch/mips/crtools.o' failed
make[2]: *** [criu/arch/mips/crtools.o] Error 1
criu/Makefile:49: recipe for target 'criu/arch/mips/crtools.built-in.o' failed
make[1]: *** [criu/arch/mips/crtools.built-in.o] Error 2
Makefile:250: recipe for target 'criu' failed
make: *** [criu] Error 2
[root@localhost criu]# grep "define kdat_can_map_vdso" . -r
./criu/arch/arm/include/asm/kerndat.h:#define kdat_can_map_vdso()			0
./criu/arch/mips/include/asm/restorer.h:#define kdat_can_map_vdso(void)			0
./criu/arch/mips/include/asm/kerndat.h:#define kdat_can_map_vdso()			0
./criu/arch/s390/include/asm/kerndat.h:#define kdat_can_map_vdso()			0
./criu/arch/aarch64/include/asm/kerndat.h:#define kdat_can_map_vdso()			0
./criu/arch/ppc64/include/asm/kerndat.h:#define kdat_can_map_vdso()			0
[root@localhost criu]# make
Note: Building without GnuTLS support
make[1]: Nothing to be done for 'all'.
make[1]: 'images/built-in.o' is up to date.
make[1]: 'compel/plugins/std.lib.a' is up to date.
make[1]: 'compel/plugins/fds.lib.a' is up to date.
make[1]: 'compel/libcompel.a' is up to date.
make[1]: 'compel/compel-host-bin' is up to date.
make[1]: Nothing to be done for 'all'.
make[1]: 'soccr/libsoccr.a' is up to date.
  DEP      criu/arch/mips/crtools.d
  CC       criu/arch/mips/crtools.o
  CC       criu/arch/mips/sigframe.o
  LINK     criu/arch/mips/crtools.built-in.o
  DEP      criu/pie/util-vdso.d
  DEP      criu/pie/util.d
  CC       criu/pie/util.o
  CC       criu/pie/util-vdso.o
  AR       criu/pie/pie.lib.a
  DEP      criu/pie/restorer.d
  DEP      criu/arch/mips/restorer.d
  DEP      criu/arch/mips/vdso-pie.d
  DEP      criu/pie/parasite-vdso.d
  DEP      criu/pie/parasite.d
  CC       criu/pie/parasite.o
  LINK     criu/pie/parasite.built-in.o
  GEN      criu/pie/parasite-blob.h
  CC       criu/pie/parasite-vdso.o
  CC       criu/arch/mips/vdso-pie.o
  CC       criu/arch/mips/restorer.o
  CC       criu/pie/restorer.o
  LINK     criu/pie/restorer.built-in.o
  GEN      criu/pie/restorer-blob.h
Error (compel/src/lib/handle-elf-host.c:336): Unexpected undefined symbol: `sys_preadv_raw'. External symbol in PIE?
criu/pie/Makefile:57: recipe for target 'criu/pie/restorer-blob.h' failed
make[2]: *** [criu/pie/restorer-blob.h] Error 255
criu/Makefile:59: recipe for target 'pie' failed
make[1]: *** [pie] Error 2
Makefile:250: recipe for target 'criu' failed
make: *** [criu] Error 2
[root@localhost criu]# grep sys_preadv_raw . -r
./compel/plugins/include/uapi/std/syscall-types.h:extern long sys_preadv_raw(int fd, struct iovec *iov, unsigned long nr, unsigned long pos_l, unsigned long pos_h);
./compel/plugins/include/uapi/std/syscall-types.h:	return sys_preadv_raw(fd, iov, nr, off, 0);
./compel/plugins/include/uapi/std/syscall-types.h:	return sys_preadv_raw(fd, iov, nr, off, ((uint64_t)off) >> 32);
./compel/arch/s390/plugins/std/syscalls/syscall-s390.tbl:__NR_preadv		328		sys_preadv_raw		(int fd, struct iovec *iov, unsigned long nr, unsigned long pos_l, unsigned long pos_h)
./compel/arch/x86/plugins/std/syscalls/syscall_64.tbl:__NR_preadv			295		sys_preadv_raw		(int fd, struct iovec *iov, unsigned long nr, unsigned long pos_l, unsigned long pos_h)
./compel/arch/x86/plugins/std/syscalls/syscall_32.tbl:__NR_preadv		333		sys_preadv_raw		(int fd, struct iovec *iov, unsigned long nr, unsigned long pos_l, unsigned long pos_h)
./compel/arch/ppc64/plugins/std/syscalls/syscall-ppc64.tbl:__NR_preadv		320		sys_preadv_raw		(int fd, struct iovec *iov, unsigned long nr, unsigned long pos_l, unsigned long pos_h)
匹配到二进制文件 ./criu/pie/restorer.o
匹配到二进制文件 ./criu/pie/restorer.built-in.o
[root@localhost criu]# 