# Define structures and constants for generating elf file.
from ctypes import *

Elf64_Half	= c_uint16	# typedef uint16_t Elf64_Half;
Elf64_Word	= c_uint32	# typedef uint32_t Elf64_Word;
Elf64_Addr	= c_uint64	# typedef uint64_t Elf64_Addr;
Elf64_Off	= c_uint64	# typedef uint64_t Elf64_Off;
Elf64_Xword	= c_uint64	# typedef uint64_t Elf64_Xword;

# Elf64_Ehdr related constants.

# e_ident size.
EI_NIDENT	= 16		# #define EI_NIDENT (16)

EI_MAG0		= 0		# #define EI_MAG0         0               /* File identification byte 0 index */
ELFMAG0		= 0x7f		# #define ELFMAG0         0x7f            /* Magic number byte 0 */

EI_MAG1		= 1		# #define EI_MAG1         1               /* File identification byte 1 index */
ELFMAG1		= ord('E')	# #define ELFMAG1         'E'             /* Magic number byte 1 */

EI_MAG2		= 2		# #define EI_MAG2         2               /* File identification byte 2 index */
ELFMAG2		= ord('L')	# #define ELFMAG2         'L'             /* Magic number byte 2 */

EI_MAG3		= 3		# #define EI_MAG3         3               /* File identification byte 3 index */
ELFMAG3		= ord('F')	# #define ELFMAG3         'F'             /* Magic number byte 3 */

EI_CLASS	= 4		# #define EI_CLASS        4               /* File class byte index */

EI_DATA		= 5		# #define EI_DATA         5               /* Data encoding byte index */

EI_VERSION	= 6		# #define EI_VERSION      6               /* File version byte index */

ELFDATA2LSB	= 1		# #define ELFDATA2LSB     1               /* 2's complement, little endian */

ELFCLASS64	= 2		# #define ELFCLASS64      2               /* 64-bit objects */

# Legal values for e_type (object file type).
ET_CORE		= 4		# #define ET_CORE         4               /* Core file */

# Legal values for e_machine (architecture).
EM_X86_64	= 62		# #define EM_X86_64       62              /* AMD x86-64 architecture */

# Legal values for e_version (version).
EV_CURRENT	= 1		# #define EV_CURRENT      1               /* Current version */

class Elf64_Ehdr(Structure):			# typedef struct
	_fields_ = [				# {
	("e_ident",	c_ubyte*EI_NIDENT),	#   unsigned char e_ident[EI_NIDENT];
	("e_type",	Elf64_Half),		#   Elf64_Half e_type;
	("e_machine",	Elf64_Half),		#   Elf64_Half e_machine;
	("e_version",	Elf64_Word),		#   Elf64_Word e_version;
	("e_entry",	Elf64_Addr),		#   Elf64_Addr e_entry;
	("e_phoff",	Elf64_Off),		#   Elf64_Off e_phoff;
	("e_shoff",	Elf64_Off),		#   Elf64_Off e_shoff;
	("e_flags",	Elf64_Word),		#   Elf64_Word e_flags;
	("e_ehsize",	Elf64_Half),		#   Elf64_Half e_ehsize;
	("e_phentsize",	Elf64_Half),		#   Elf64_Half e_phentsize;
	("e_phnum",	Elf64_Half),		#   Elf64_Half e_phnum;
	("e_shentsize",	Elf64_Half),		#   Elf64_Half e_shentsize;
	("e_shnum",	Elf64_Half),		#   Elf64_Half e_shnum;
	("e_shstrndx",	Elf64_Half)		#   Elf64_Half e_shstrndx;
	]					# } Elf64_Ehdr;


# Elf64_Phdr related constants.

# Legal values for p_type (segment type).
PT_LOAD	= 1		# #define PT_LOAD         1               /* Loadable program segment */
PT_NOTE	= 4		# #define PT_NOTE         4               /* Auxiliary information */

# Legal values for p_flags (segment flags).
PF_X	= 1		# #define PF_X            (1 << 0)        /* Segment is executable */
PF_W	= 1 << 1	# #define PF_W            (1 << 1)        /* Segment is writable */
PF_R	= 1 << 2	# #define PF_R            (1 << 2)        /* Segment is readable */

class Elf64_Phdr(Structure):			# typedef struct
	_fields_ = [				# {
	("p_type",	Elf64_Word),		#   Elf64_Word p_type;
	("p_flags",	Elf64_Word),		#   Elf64_Word p_flags;
	("p_offset",	Elf64_Off),		#   Elf64_Off p_offset;
	("p_vaddr",	Elf64_Addr),		#   Elf64_Addr p_vaddr;
	("p_paddr",	Elf64_Addr),		#   Elf64_Addr p_paddr;
	("p_filesz",	Elf64_Xword),		#   Elf64_Xword p_filesz;
	("p_memsz",	Elf64_Xword),		#   Elf64_Xword p_memsz;
	("p_align",	Elf64_Xword),		#   Elf64_Xword p_align;
	]					# } Elf64_Phdr;


# Elf64_auxv_t related constants.

class _Elf64_auxv_t_U(Union):
	_fields_ = [
	("a_val", c_uint64)
	]

class Elf64_auxv_t(Structure):			# typedef struct
	_fields_ = [				# {
	("a_type",	c_uint64),		#   uint64_t a_type;              /* Entry type */
	("a_un",	_Elf64_auxv_t_U)	#   union
						#     {
						#       uint64_t a_val;           /* Integer value */
						#       /* We use to have pointer elements added here.  We cannot do that,
						#          though, since it does not work when using 32-bit definitions
						#          on 64-bit platforms and vice versa.  */
						#     } a_un;
	]					# } Elf64_auxv_t;


# Elf64_Nhdr related constants.

NT_PRSTATUS	= 1		# #define NT_PRSTATUS     1               /* Contains copy of prstatus struct */
NT_FPREGSET	= 2		# #define NT_FPREGSET     2               /* Contains copy of fpregset struct */
NT_PRPSINFO	= 3		# #define NT_PRPSINFO     3               /* Contains copy of prpsinfo struct */
NT_AUXV		= 6		# #define NT_AUXV         6               /* Contains copy of auxv array */
NT_SIGINFO	= 0x53494749	# #define NT_SIGINFO      0x53494749      /* Contains copy of siginfo_t,
#									     size might increase */
NT_FILE		= 0x46494c45	# #define NT_FILE         0x46494c45      /* Contains information about mapped
#									     files */
NT_X86_XSTATE	= 0x202		# #define NT_X86_XSTATE   0x202           /* x86 extended state using xsave */

class Elf64_Nhdr(Structure):		# typedef struct
	_fields_ = [			# {
	("n_namesz",	Elf64_Word),	#   Elf64_Word n_namesz;                  /* Length of the note's name.  */
	("n_descsz",	Elf64_Word),	#   Elf64_Word n_descsz;                  /* Length of the note's descriptor.  */
	("n_type",	Elf64_Word),	#   Elf64_Word n_type;                    /* Type of the note.  */
	]				# } Elf64_Nhdr;


# Elf64_Shdr related constants.

class Elf64_Shdr(Structure):		# typedef struct
	_fields_ = [			# {
	("sh_name",	Elf64_Word),	#   Elf64_Word    sh_name;                /* Section name (string tbl index) */
	("sh_type",	Elf64_Word),	#   Elf64_Word    sh_type;                /* Section type */
	("sh_flags",	Elf64_Xword),	#   Elf64_Xword   sh_flags;               /* Section flags */
	("sh_addr",	Elf64_Addr),	#   Elf64_Addr    sh_addr;                /* Section virtual addr at execution */
	("sh_offset",	Elf64_Off),	#   Elf64_Off     sh_offset;              /* Section file offset */
	("sh_size",	Elf64_Xword),	#   Elf64_Xword   sh_size;                /* Section size in bytes */
	("sh_link",	Elf64_Word),	#   Elf64_Word    sh_link;                /* Link to another section */
	("sh_info",	Elf64_Word),	#   Elf64_Word    sh_info;                /* Additional section information */
	("sh_addralign",Elf64_Xword),	#   Elf64_Xword   sh_addralign;           /* Section alignment */
	("sh_entsize",	Elf64_Xword)	#   Elf64_Xword   sh_entsize;             /* Entry size if section holds table */
	]				# } Elf64_Shdr;


# elf_prstatus related constants.

# Signal info.
class elf_siginfo(Structure):		# struct elf_siginfo
	_fields_ = [			#   {
	("si_signo",	c_int),		#     int si_signo;                       /* Signal number.  */
	("si_code",	c_int),		#     int si_code;                        /* Extra code.  */
	("si_errno",	c_int)		#     int si_errno;                       /* Errno.  */
	]				#   };

# A time value that is accurate to the nearest
# microsecond but also has a range of years.
class timeval(Structure):		# struct timeval
	_fields_ = [			#   {
	("tv_sec",	c_long),	#     __time_t tv_sec;            /* Seconds.  */
	("tv_usec",	c_long)		#     __suseconds_t tv_usec;      /* Microseconds.  */
	]				#   };

class user_regs_struct(Structure):		# struct user_regs_struct
	_fields_ = [				# {
	("r15",		c_ulonglong),		#   __extension__ unsigned long long int r15;
	("r14",		c_ulonglong),		#   __extension__ unsigned long long int r14;
	("r13",		c_ulonglong),		#   __extension__ unsigned long long int r13;
	("r12",		c_ulonglong),		#   __extension__ unsigned long long int r12;
	("rbp",		c_ulonglong),		#   __extension__ unsigned long long int rbp;
	("rbx",		c_ulonglong),		#   __extension__ unsigned long long int rbx;
	("r11",		c_ulonglong),		#   __extension__ unsigned long long int r11;
	("r10",		c_ulonglong),		#   __extension__ unsigned long long int r10;
	("r9",		c_ulonglong),		#   __extension__ unsigned long long int r9;
	("r8",		c_ulonglong),		#   __extension__ unsigned long long int r8;
	("rax",		c_ulonglong),		#   __extension__ unsigned long long int rax;
	("rcx",		c_ulonglong),		#   __extension__ unsigned long long int rcx;
	("rdx",		c_ulonglong),		#   __extension__ unsigned long long int rdx;
	("rsi",		c_ulonglong),		#   __extension__ unsigned long long int rsi;
	("rdi",		c_ulonglong),		#   __extension__ unsigned long long int rdi;
	("orig_rax",	c_ulonglong),		#   __extension__ unsigned long long int orig_rax;
	("rip",		c_ulonglong),		#   __extension__ unsigned long long int rip;
	("cs",		c_ulonglong),		#   __extension__ unsigned long long int cs;
	("eflags",	c_ulonglong),		#   __extension__ unsigned long long int eflags;
	("rsp",		c_ulonglong),		#   __extension__ unsigned long long int rsp;
	("ss",		c_ulonglong),		#   __extension__ unsigned long long int ss;
	("fs_base",	c_ulonglong),		#   __extension__ unsigned long long int fs_base;
	("gs_base",	c_ulonglong),		#   __extension__ unsigned long long int gs_base;
	("ds",		c_ulonglong),		#   __extension__ unsigned long long int ds;
	("es",		c_ulonglong),		#   __extension__ unsigned long long int es;
	("fs",		c_ulonglong),		#   __extension__ unsigned long long int fs;
	("gs",		c_ulonglong)		#   __extension__ unsigned long long int gs;
	]					# };

#elf_greg_t	= c_ulonglong
#ELF_NGREG = sizeof(user_regs_struct)/sizeof(elf_greg_t)
#elf_gregset_t = elf_greg_t*ELF_NGREG
elf_gregset_t = user_regs_struct

class elf_prstatus(Structure):		# struct elf_prstatus
	_fields_ = [			#   {
	("pr_info",	elf_siginfo),	#     struct elf_siginfo pr_info;         /* Info associated with signal.  */
	("pr_cursig",	c_short),	#     short int pr_cursig;                /* Current signal.  */
	("pr_sigpend",	c_ulong),	#     unsigned long int pr_sigpend;       /* Set of pending signals.  */
	("pr_sighold",	c_ulong),	#     unsigned long int pr_sighold;       /* Set of held signals.  */
	("pr_pid",	c_int),		#     __pid_t pr_pid;
	("pr_ppid",	c_int),		#     __pid_t pr_ppid;
	("pr_pgrp",	c_int),		#     __pid_t pr_pgrp;
	("pr_sid",	c_int),		#     __pid_t pr_sid;
	("pr_utime",	timeval),	#     struct timeval pr_utime;            /* User time.  */
	("pr_stime",	timeval),	#     struct timeval pr_stime;            /* System time.  */
	("pr_cutime",	timeval),	#     struct timeval pr_cutime;           /* Cumulative user time.  */
	("pr_cstime",	timeval),	#     struct timeval pr_cstime;           /* Cumulative system time.  */
	("pr_reg",	elf_gregset_t),	#     elf_gregset_t pr_reg;               /* GP registers.  */
	("pr_fpvalid",	c_int)		#     int pr_fpvalid;                     /* True if math copro being used.  */
	]				#   };


# elf_prpsinfo related constants.

ELF_PRARGSZ	= 80			# #define ELF_PRARGSZ     (80)    /* Number of chars for args.  */

class elf_prpsinfo(Structure):			# struct elf_prpsinfo
	_fields_ = [				#   {
	("pr_state",	c_byte),		#     char pr_state;                      /* Numeric process state.  */
	("pr_sname",	c_char),		#     char pr_sname;                      /* Char for pr_state.  */
	("pr_zomb",	c_byte),		#     char pr_zomb;                       /* Zombie.  */
	("pr_nice",	c_byte),		#     char pr_nice;                       /* Nice val.  */
	("pr_flag",	c_ulong),		#     unsigned long int pr_flag;          /* Flags.  */
						# #if __WORDSIZE == 32
						#     unsigned short int pr_uid;
						#     unsigned short int pr_gid;
						# #else
	("pr_uid",	c_uint),		#     unsigned int pr_uid;
	("pr_gid",	c_uint),		#     unsigned int pr_gid;
						# #endif
	("pr_pid",	c_int),			#     int pr_pid, pr_ppid, pr_pgrp, pr_sid;
	("pr_ppid",	c_int),
	("pr_pgrp",	c_int),
	("pr_sid",	c_int),
						#     /* Lots missing */
	("pr_fname",	c_char*16),		#     char pr_fname[16];                  /* Filename of executable.  */
	("pr_psargs",	c_char*ELF_PRARGSZ)	#     char pr_psargs[ELF_PRARGSZ];        /* Initial part of arg list.  */
	]					#   };


class user_fpregs_struct(Structure):		# struct user_fpregs_struct
	_fields_ = [				# {
	("cwd",		c_ushort),		#   unsigned short int    cwd;
	("swd",		c_ushort),		#   unsigned short int    swd;
	("ftw",		c_ushort),		#   unsigned short int    ftw;
	("fop",		c_ushort),		#   unsigned short int    fop;
	("rip",		c_ulonglong),		#   __extension__ unsigned long long int rip;
	("rdp",		c_ulonglong),		#   __extension__ unsigned long long int rdp;
	("mxcsr",	c_uint),		#   unsigned int          mxcsr;
	("mxcr_mask",	c_uint),		#   unsigned int          mxcr_mask;
	("st_space",	c_uint*32),		#   unsigned int          st_space[32];   /* 8*16 bytes for each FP-reg = 128 bytes */
	("xmm_space",	c_uint*64),		#   unsigned int          xmm_space[64];  /* 16*16 bytes for each XMM-reg = 256 bytes */
	("padding",	c_uint*24),		#   unsigned int          padding[24];
	]					# };


elf_fpregset_t = user_fpregs_struct


# siginfo_t related constants.

_SI_MAX_SIZE	= 128
_SI_PAD_SIZE	= (_SI_MAX_SIZE/sizeof(c_int)) - 4

					#          /* kill().  */
class _siginfo_t_U_kill(Structure):	#         struct
	_fields_ = [			#           {
	("si_pid",	c_int),		#             __pid_t si_pid;     /* Sending process ID.  */
	("si_uid",	c_uint)		#             __uid_t si_uid;     /* Real user ID of sending process.  */
	]				#           } _kill;



# Type for data associated with a signal.
class sigval_t(Union):			# typedef union sigval
	_fields_ = [			#   {
	("sival_int", c_int),		#     int sival_int;
	("sical_ptr", c_void_p),	#     void *sival_ptr;
	]				#   } sigval_t;

					#         /* POSIX.1b timers.  */
class _siginfo_t_U_timer(Structure):	#         struct
	_fields_ = [			#           {
	("si_tid",	c_int),		#             int si_tid;         /* Timer ID.  */
	("si_overrun",	c_int),		#             int si_overrun;     /* Overrun count.  */
	("si_sigval",	sigval_t)	#             sigval_t si_sigval; /* Signal value.  */
	]				#           } _timer;


						#         /* POSIX.1b signals.  */
class _siginfo_t_U_rt(Structure):		#         struct
	_fields_ = [				#           {
	("si_pid",	c_int),			#             __pid_t si_pid;     /* Sending process ID.  */
	("si_uid",	c_uint),		#             __uid_t si_uid;     /* Real user ID of sending process.  */
	("si_sigval",	sigval_t)		#             sigval_t si_sigval; /* Signal value.  */
	]					#           } _rt;


						#         /* SIGCHLD.  */
class _siginfo_t_U_sigchld(Structure):		#         struct
	_fields_ = [				#           {
	("si_pid",	c_int),			#             __pid_t si_pid;     /* Which child.  */
	("si_uid",	c_uint),		#             __uid_t si_uid;     /* Real user ID of sending process.  */
	("si_status",	c_int),			#             int si_status;      /* Exit value or signal.  */
	("si_utime",	c_long),		#             __sigchld_clock_t si_utime;
	("si_stime",	c_long)			#             __sigchld_clock_t si_stime;
	]					#           } _sigchld;

						#         /* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
class _siginfo_t_U_sigfault(Structure):		#         struct
	_fields_ = [				#           {
	("si_addr",	c_void_p),		#             void *si_addr;      /* Faulting insn/memory ref.  */
	("si_addr_lsb",	c_short)		#             short int si_addr_lsb;      /* Valid LSB of the reported address.  */
	]					#           } _sigfault;

						#         /* SIGPOLL.  */
class _siginfo_t_U_sigpoll(Structure):		#         struct
	_fields_ = [				#           {
	("si_band",	c_long),		#             long int si_band;   /* Band event for SIGPOLL.  */
	("si_fd",	c_int)			#             int si_fd;
	]					#           } _sigpoll;


						# 	        /* SIGSYS.  */
class _siginfo_t_U_sigsys(Structure):		#         struct
	_fields_ = [				#           {
	("_call_addr",	c_void_p),		#             void *_call_addr;   /* Calling user insn.  */
	("_syscall",	c_int),			#             int _syscall;       /* Triggering system call number.  */
	("_arch",	c_uint)			#             unsigned int _arch; /* AUDIT_ARCH_* of syscall.  */
	]					#           } _sigsys;


class _siginfo_t_U(Union):			#     union
	_fields_ = [				#       {
	("_pad",	c_int*_SI_PAD_SIZE),	#         int _pad[__SI_PAD_SIZE];
						#
						#          /* kill().  */
	("_kill",	_siginfo_t_U_kill),	#         struct
						#           {
						#             __pid_t si_pid;     /* Sending process ID.  */
						#             __uid_t si_uid;     /* Real user ID of sending process.  */
						#           } _kill;
						#
						#         /* POSIX.1b timers.  */
	("_timer",	_siginfo_t_U_timer),	#         struct
						#           {
						#             int si_tid;         /* Timer ID.  */
						#             int si_overrun;     /* Overrun count.  */
						#             sigval_t si_sigval; /* Signal value.  */
						#           } _timer;
						#
						#         /* POSIX.1b signals.  */
	("_rt",		_siginfo_t_U_rt),	#         struct
						#           {
						#             __pid_t si_pid;     /* Sending process ID.  */
						#             __uid_t si_uid;     /* Real user ID of sending process.  */
						#             sigval_t si_sigval; /* Signal value.  */
						#           } _rt;
						#
						#         /* SIGCHLD.  */
	("_sigchld",	_siginfo_t_U_sigchld),	#         struct
						#           {
						#             __pid_t si_pid;     /* Which child.  */
						#             __uid_t si_uid;     /* Real user ID of sending process.  */
						#             int si_status;      /* Exit value or signal.  */
						#             __sigchld_clock_t si_utime;
						#             __sigchld_clock_t si_stime;
						#           } _sigchld;
						#
						#         /* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
	("_sigfault",	_siginfo_t_U_sigfault),	#         struct
						#           {
						#             void *si_addr;      /* Faulting insn/memory ref.  */
						#             short int si_addr_lsb;      /* Valid LSB of the reported address.  */
						#           } _sigfault;
						#
						#         /* SIGPOLL.  */
	("_sigpoll",	_siginfo_t_U_sigpoll),	#         struct
						#           {
						#             long int si_band;   /* Band event for SIGPOLL.  */
						#             int si_fd;
						#           } _sigpoll;
						#
						# 	        /* SIGSYS.  */
	("_sigsys",	_siginfo_t_U_sigpoll)	#         struct
						#           {
						#             void *_call_addr;   /* Calling user insn.  */
						#             int _syscall;       /* Triggering system call number.  */
						#             unsigned int _arch; /* AUDIT_ARCH_* of syscall.  */
						#           } _sigsys;
	]					#       } _sifields;

class siginfo_t(Structure):		# typedef struct
	_fields_ = [			#   {
	("si_signo",	c_int),		#     int si_signo;               /* Signal number.  */
	("si_errno",	c_int),		#     int si_errno;               /* If non-zero, an errno value associated with
					#                                    this signal, as defined in <errno.h>.  */
	("si_code",	c_int),		#     int si_code;                /* Signal code.  */
					#
	("_sifields",	_siginfo_t_U)	#     union
					#       {
					#         int _pad[__SI_PAD_SIZE];
					#
					#          /* kill().  */
					#         struct
					#           {
					#             __pid_t si_pid;     /* Sending process ID.  */
					#             __uid_t si_uid;     /* Real user ID of sending process.  */
					#           } _kill;
					#
					#         /* POSIX.1b timers.  */
					#         struct
					#           {
					#             int si_tid;         /* Timer ID.  */
					#             int si_overrun;     /* Overrun count.  */
					#             sigval_t si_sigval; /* Signal value.  */
					#           } _timer;
					#
					#         /* POSIX.1b signals.  */
					#         struct
					#           {
					#             __pid_t si_pid;     /* Sending process ID.  */
					#             __uid_t si_uid;     /* Real user ID of sending process.  */
					#             sigval_t si_sigval; /* Signal value.  */
					#           } _rt;
					#
					#         /* SIGCHLD.  */
					#         struct
					#           {
					#             __pid_t si_pid;     /* Which child.  */
					#             __uid_t si_uid;     /* Real user ID of sending process.  */
					#             int si_status;      /* Exit value or signal.  */
					#             __sigchld_clock_t si_utime;
					#             __sigchld_clock_t si_stime;
					#           } _sigchld;
					#
					#         /* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
					#         struct
					#           {
					#             void *si_addr;      /* Faulting insn/memory ref.  */
					#             short int si_addr_lsb;      /* Valid LSB of the reported address.  */
					#           } _sigfault;
					#
					#         /* SIGPOLL.  */
					#         struct
					#           {
					#             long int si_band;   /* Band event for SIGPOLL.  */
					#             int si_fd;
					#           } _sigpoll;
					#
					# 	        /* SIGSYS.  */
					#         struct
					#           {
					#             void *_call_addr;   /* Calling user insn.  */
					#             int _syscall;       /* Triggering system call number.  */
					#             unsigned int _arch; /* AUDIT_ARCH_* of syscall.  */
					#           } _sigsys;
					#       } _sifields;
	]				#   } siginfo_t __SI_ALIGNMENT;


# xsave related.

class ymmh_struct(Structure):		# struct ymmh_struct {
	_fields_ = [
	("ymmh_space",	64*c_uint)	#         u32                             ymmh_space[64];
	]				# } __packed;


class xsave_hdr_struct(Structure):	# struct xsave_hdr_struct {
	_fields_ = [
	("xstate_bv",	c_ulonglong),	#         u64                             xstate_bv;
	("reserved1",	c_ulonglong*2),	#         u64                             reserved1[2];
	("reserved2",	c_ulonglong*5)	#         u64                             reserved2[5];
	]				# } __packed;


class i387_fxsave_struct(Structure):	# struct i387_fxsave_struct {
	_fields_ = [
	("cwd",		c_ushort),	#         u16                             cwd; /* Control Word                    */
	("swd",		c_ushort),	#         u16                             swd; /* Status Word                     */
	("twd",		c_ushort),	#         u16                             twd; /* Tag Word                        */
	("fop",		c_ushort),	#         u16                             fop; /* Last Instruction Opcode         */
					#         union {
					#                 struct {
	("rip",		c_ulonglong),	#                         u64             rip; /* Instruction Pointer             */
	("rdp",		c_ulonglong),	#                         u64             rdp; /* Data Pointer                    */
					#                 };
					#                 struct {
					#                         u32             fip; /* FPU IP Offset                   */
					#                         u32             fcs; /* FPU IP Selector                 */
					#                         u32             foo; /* FPU Operand Offset              */
					#                         u32             fos; /* FPU Operand Selector            */
					#                 };
					#         };
	("mxcsr",	c_uint),	#         u32                             mxcsr;          /* MXCSR Register State */
	("mxcsr_mask",	c_uint),	#         u32                             mxcsr_mask;     /* MXCSR Mask           */
					#
					#         /* 8*16 bytes for each FP-reg = 128 bytes                               */
	("st_space",	c_uint*32),	#         u32                             st_space[32];
#
					#         /* 16*16 bytes for each XMM-reg = 256 bytes                             */
	("xmm_space",	c_uint*64),	#         u32                             xmm_space[64];
					#
	("padding",	c_uint*12),	#         u32                             padding[12];
					#
					#         union {
	("padding1",	c_uint*12)	#                 u32                     padding1[12];
					#                 u32                     sw_reserved[12];
					#         };
					#
	]				# } __aligned(16);


class elf_xsave_struct(Structure):		# struct xsave_struct {
	_fields_ = [
	("i387",	i387_fxsave_struct),	#         struct i387_fxsave_struct       i387;
	("xsave_hdr",	xsave_hdr_struct),	#         struct xsave_hdr_struct         xsave_hdr;
	("ymmh",	ymmh_struct)		#         struct ymmh_struct              ymmh;
	]					# } __aligned(FP_MIN_ALIGN_BYTES) __packed;
