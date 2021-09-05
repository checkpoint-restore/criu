# Define structures and constants for generating elf file.
import ctypes

Elf64_Half = ctypes.c_uint16  # typedef uint16_t Elf64_Half;
Elf64_Word = ctypes.c_uint32  # typedef uint32_t Elf64_Word;
Elf64_Addr = ctypes.c_uint64  # typedef uint64_t Elf64_Addr;
Elf64_Off = ctypes.c_uint64  # typedef uint64_t Elf64_Off;
Elf64_Xword = ctypes.c_uint64  # typedef uint64_t Elf64_Xword;

# Elf64_Ehdr related constants.

# e_ident size.
EI_NIDENT = 16  # #define EI_NIDENT (16)

EI_MAG0 = 0  # #define EI_MAG0         0               /* File identification byte 0 index */
ELFMAG0 = 0x7f  # #define ELFMAG0         0x7f            /* Magic number byte 0 */

EI_MAG1 = 1  # #define EI_MAG1         1               /* File identification byte 1 index */
ELFMAG1 = ord('E')  # #define ELFMAG1  'E'             /* Magic number byte 1 */

EI_MAG2 = 2  # #define EI_MAG2         2               /* File identification byte 2 index */
ELFMAG2 = ord('L')  # #define ELFMAG2  'L'             /* Magic number byte 2 */

EI_MAG3 = 3  # #define EI_MAG3         3               /* File identification byte 3 index */
ELFMAG3 = ord('F')  # #define ELFMAG3  'F'             /* Magic number byte 3 */

EI_CLASS = 4  # #define EI_CLASS        4               /* File class byte index */

EI_DATA = 5  # #define EI_DATA         5               /* Data encoding byte index */

EI_VERSION = 6  # #define EI_VERSION      6               /* File version byte index */

ELFDATA2LSB = 1  # #define ELFDATA2LSB     1               /* 2's complement, little endian */

ELFCLASS64 = 2  # #define ELFCLASS64      2               /* 64-bit objects */

# Legal values for e_type (object file type).
ET_CORE = 4  # #define ET_CORE         4               /* Core file */

# Legal values for e_machine (architecture).
EM_X86_64 = 62  # #define EM_X86_64       62              /* AMD x86-64 architecture */

# Legal values for e_version (version).
EV_CURRENT = 1  # #define EV_CURRENT      1               /* Current version */


class Elf64_Ehdr(ctypes.Structure):  # typedef struct
    _fields_ = [
        ("e_ident",
         ctypes.c_ubyte * EI_NIDENT),  # unsigned char e_ident[EI_NIDENT];
        ("e_type", Elf64_Half),  # Elf64_Half e_type;
        ("e_machine", Elf64_Half),  # Elf64_Half e_machine;
        ("e_version", Elf64_Word),  # Elf64_Word e_version;
        ("e_entry", Elf64_Addr),  # Elf64_Addr e_entry;
        ("e_phoff", Elf64_Off),  # Elf64_Off e_phoff;
        ("e_shoff", Elf64_Off),  # Elf64_Off e_shoff;
        ("e_flags", Elf64_Word),  # Elf64_Word e_flags;
        ("e_ehsize", Elf64_Half),  # Elf64_Half e_ehsize;
        ("e_phentsize", Elf64_Half),  # Elf64_Half e_phentsize;
        ("e_phnum", Elf64_Half),  # Elf64_Half e_phnum;
        ("e_shentsize", Elf64_Half),  # Elf64_Half e_shentsize;
        ("e_shnum", Elf64_Half),  # Elf64_Half e_shnum;
        ("e_shstrndx", Elf64_Half)  # Elf64_Half e_shstrndx;
    ]  # } Elf64_Ehdr;


# Elf64_Phdr related constants.

# Legal values for p_type (segment type).
PT_LOAD = 1  # #define PT_LOAD         1               /* Loadable program segment */
PT_NOTE = 4  # #define PT_NOTE         4               /* Auxiliary information */

# Legal values for p_flags (segment flags).
PF_X = 1  # #define PF_X            (1 << 0)        /* Segment is executable */
PF_W = 1 << 1  # #define PF_W            (1 << 1)        /* Segment is writable */
PF_R = 1 << 2  # #define PF_R            (1 << 2)        /* Segment is readable */


class Elf64_Phdr(ctypes.Structure):  # typedef struct
    _fields_ = [
        ("p_type", Elf64_Word),  # Elf64_Word p_type;
        ("p_flags", Elf64_Word),  # Elf64_Word p_flags;
        ("p_offset", Elf64_Off),  # Elf64_Off p_offset;
        ("p_vaddr", Elf64_Addr),  # Elf64_Addr p_vaddr;
        ("p_paddr", Elf64_Addr),  # Elf64_Addr p_paddr;
        ("p_filesz", Elf64_Xword),  # Elf64_Xword p_filesz;
        ("p_memsz", Elf64_Xword),  # Elf64_Xword p_memsz;
        ("p_align", Elf64_Xword),  # Elf64_Xword p_align;
    ]  # } Elf64_Phdr;


# Elf64_auxv_t related constants.


class _Elf64_auxv_t_U(ctypes.Union):
    _fields_ = [("a_val", ctypes.c_uint64)]


class Elf64_auxv_t(ctypes.Structure):  # typedef struct
    _fields_ = [
        ("a_type",
         ctypes.c_uint64),  # uint64_t a_type;              /* Entry type */
        ("a_un", _Elf64_auxv_t_U)  # union

        # uint64_t a_val;           /* Integer value */
        # /* We use to have pointer elements added here.  We cannot do that,
        # though, since it does not work when using 32-bit definitions
        # on 64-bit platforms and vice versa.  */
        # } a_un;
    ]  # } Elf64_auxv_t;


# Elf64_Nhdr related constants.

NT_PRSTATUS = 1  # #define NT_PRSTATUS  1  /* Contains copy of prstatus struct */
NT_FPREGSET = 2  # #define NT_FPREGSET  2  /* Contains copy of fpregset struct */
NT_PRPSINFO = 3  # #define NT_PRPSINFO  3  /* Contains copy of prpsinfo struct */
NT_AUXV = 6  # #define NT_AUXV  6  /* Contains copy of auxv array */
NT_SIGINFO = 0x53494749  # #define NT_SIGINFO  0x53494749  /* Contains copy of siginfo_t, size might increase */
NT_FILE = 0x46494c45  # #define NT_FILE  0x46494c45  /* Contains information about mapped files */
NT_X86_XSTATE = 0x202  # #define NT_X86_XSTATE  0x202  /* x86 extended state using xsave */


class Elf64_Nhdr(ctypes.Structure):  # typedef struct
    _fields_ = [
        (
            "n_namesz", Elf64_Word
        ),  # Elf64_Word n_namesz;  /* Length of the note's name.  */
        (
            "n_descsz", Elf64_Word
        ),  # Elf64_Word n_descsz;  /* Length of the note's descriptor.  */
        ("n_type", Elf64_Word
         ),  # Elf64_Word n_type;  /* Type of the note.  */
    ]  # } Elf64_Nhdr;


# Elf64_Shdr related constants.


class Elf64_Shdr(ctypes.Structure):
    _fields_ = [
        (
            # Section name (string tbl index)
            "sh_name", Elf64_Word
        ),
        (
            # Section type
            "sh_type", Elf64_Word
        ),
        (
            # Section flags
            "sh_flags", Elf64_Xword
        ),
        (
            # Section virtual addr at execution
            "sh_addr", Elf64_Addr
        ),
        (
            # Section file offset
            "sh_offset", Elf64_Off
        ),
        (
            # Section size in bytes
            "sh_size", Elf64_Xword
        ),
        (
            # Link to another section
            "sh_link", Elf64_Word
        ),
        (
            # Additional section information
            "sh_info", Elf64_Word
        ),
        (
            # Section alignment
            "sh_addralign", Elf64_Xword
        ),
        (
            # Entry size if section holds table
            "sh_entsize", Elf64_Xword
        )
    ]


# elf_prstatus related constants.


# Signal info.
class elf_siginfo(ctypes.Structure):  # struct elf_siginfo
    _fields_ = [
        (
            # Signal number
            "si_signo", ctypes.c_int
        ),
        (
            # Extra code
            "si_code", ctypes.c_int
        ),
        (
            # Errno
            "si_errno", ctypes.c_int
        )
    ]


# A time value that is accurate to the nearest
# microsecond but also has a range of years.
class timeval(ctypes.Structure):  # struct timeval
    _fields_ = [
        (
            # __time_t tv_sec;            /* Seconds.  */
            "tv_sec", ctypes.c_long
        ),
        (
            # __suseconds_t tv_usec;      /* Microseconds.  */
            "tv_usec", ctypes.c_long
        )
    ]


class user_regs_struct(ctypes.Structure):  # struct user_regs_struct
    _fields_ = [
        ("r15",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int r15;
        ("r14",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int r14;
        ("r13",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int r13;
        ("r12",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int r12;
        ("rbp",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int rbp;
        ("rbx",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int rbx;
        ("r11",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int r11;
        ("r10",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int r10;
        ("r9",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int r9;
        ("r8",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int r8;
        ("rax",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int rax;
        ("rcx",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int rcx;
        ("rdx",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int rdx;
        ("rsi",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int rsi;
        ("rdi",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int rdi;
        ("orig_rax", ctypes.c_ulonglong
         ),  # __extension__ unsigned long long int orig_rax;
        ("rip",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int rip;
        ("cs",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int cs;
        ("eflags",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int eflags;
        ("rsp",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int rsp;
        ("ss",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int ss;
        ("fs_base", ctypes.c_ulonglong
         ),  # __extension__ unsigned long long int fs_base;
        ("gs_base", ctypes.c_ulonglong
         ),  # __extension__ unsigned long long int gs_base;
        ("ds",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int ds;
        ("es",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int es;
        ("fs",
         ctypes.c_ulonglong),  # __extension__ unsigned long long int fs;
        ("gs", ctypes.c_ulonglong
         )  # __extension__ unsigned long long int gs;
    ]


# elf_greg_t    = ctypes.c_ulonglong
# ELF_NGREG = ctypes.sizeof(user_regs_struct)/ctypes.sizeof(elf_greg_t)
# elf_gregset_t = elf_greg_t*ELF_NGREG
elf_gregset_t = user_regs_struct


class elf_prstatus(ctypes.Structure):  # struct elf_prstatus
    _fields_ = [
        (
            # Info associated with signal
            # struct elf_siginfo pr_info;
            "pr_info", elf_siginfo
        ),
        (
            # Current signal
            # short int pr_cursig;
            "pr_cursig", ctypes.c_short
        ),
        (
            # Set of pending signals
            # unsigned long int pr_sigpend;
            "pr_sigpend", ctypes.c_ulong
        ),
        (
            # Set of held signals
            # unsigned long int pr_sighold;
            "pr_sighold", ctypes.c_ulong
        ),
        (
            # Process ID
            # __pid_t pr_pid;
            "pr_pid", ctypes.c_int
        ),
        (
            # Parent process ID
            # __pid_t pr_ppid;
            "pr_ppid", ctypes.c_int
        ),
        (
            # Parent group ID
            # __pid_t pr_pgrp;
            "pr_pgrp", ctypes.c_int
        ),
        (
            # Parent session ID
            # __pid_t pr_sid;
            "pr_sid", ctypes.c_int
        ),
        (
            # User time
            # struct timeval pr_utime;
            "pr_utime", timeval
        ),
        (
            # System time
            # struct timeval pr_stime;
            "pr_stime", timeval
        ),
        (
            # Cumulative user time
            # struct timeval pr_cutime;
            "pr_cutime", timeval
        ),
        (
            # Cumulative system time
            # struct timeval pr_cstime;
            "pr_cstime", timeval
        ),
        (
            # GP registers
            # elf_gregset_t pr_reg;
            "pr_reg", elf_gregset_t
        ),
        (
            # True if math copro being used
            # int pr_fpvalid;
            "pr_fpvalid", ctypes.c_int
        )
    ]


# elf_prpsinfo related constants.

# Number of chars for args
# #define ELF_PRARGSZ     (80)
ELF_PRARGSZ = 80


class elf_prpsinfo(ctypes.Structure):  # struct elf_prpsinfo
    _fields_ = [
        (
            # Numeric process state
            # char pr_state;
            "pr_state", ctypes.c_byte
        ),
        (
            # Char for pr_state
            # char pr_sname;
            "pr_sname", ctypes.c_char
        ),
        (
            # Zombie
            # char pr_zomb;
            "pr_zomb", ctypes.c_byte
        ),
        (
            # Nice value
            # char pr_nice;
            "pr_nice", ctypes.c_byte
        ),
        (
            # Flags
            # unsigned long int pr_flag;
            "pr_flag", ctypes.c_ulong
        ),
        (
            # User ID
            # unsigned int pr_uid;
            "pr_uid", ctypes.c_uint
        ),
        (
            # Group ID
            # unsigned int pr_gid;
            "pr_gid", ctypes.c_uint
        ),
        ("pr_pid", ctypes.c_int),
        ("pr_ppid", ctypes.c_int),
        ("pr_pgrp", ctypes.c_int),
        ("pr_sid", ctypes.c_int),
        # /* Lots missing */
        (
            # Filename of executable
            # char pr_fname[16];
            "pr_fname", ctypes.c_char * 16
        ),
        (
            # Initial part of arg list
            # char pr_psargs[ELF_PRARGSZ];
            "pr_psargs", ctypes.c_char * ELF_PRARGSZ
        )
    ]


class user_fpregs_struct(ctypes.Structure):  # struct user_fpregs_struct
    _fields_ = [
        # unsigned short int cwd;
        ("cwd", ctypes.c_ushort),
        # unsigned short int swd;
        ("swd", ctypes.c_ushort),
        # unsigned short int ftw;
        ("ftw", ctypes.c_ushort),
        # unsigned short int fop;
        ("fop", ctypes.c_ushort),
        # __extension__ unsigned long long int rip;
        ("rip", ctypes.c_ulonglong),
        # __extension__ unsigned long long int rdp;
        ("rdp", ctypes.c_ulonglong),
        # unsigned int mxcsr;
        ("mxcsr", ctypes.c_uint),
        # unsigned int mxcr_mask;
        ("mxcr_mask", ctypes.c_uint),
        # unsigned int st_space[32];   /* 8*16 bytes for each FP-reg = 128 bytes */
        ("st_space", ctypes.c_uint * 32),
        # unsigned int xmm_space[64];  /* 16*16 bytes for each XMM-reg = 256 bytes */
        ("xmm_space", ctypes.c_uint * 64),
        # unsigned int padding[24];
        ("padding", ctypes.c_uint * 24),
    ]


elf_fpregset_t = user_fpregs_struct

# siginfo_t related constants.

_SI_MAX_SIZE = 128
_SI_PAD_SIZE = (_SI_MAX_SIZE // ctypes.sizeof(ctypes.c_int)) - 4


# /* kill().  */
class _siginfo_t_U_kill(ctypes.Structure):  # struct
    _fields_ = [
        (
            # Sending process ID
            # __pid_t si_pid;
            "si_pid", ctypes.c_int
        ),
        (
            # Real user ID of sending process
            # __uid_t si_uid;
            "si_uid", ctypes.c_uint
        )
    ]  # } _kill;


# Type for data associated with a signal.
class sigval_t(ctypes.Union):  # typedef union sigval
    _fields_ = [
        ("sival_int", ctypes.c_int),  # int sival_int;
        ("sical_ptr", ctypes.c_void_p),  # void *sival_ptr;
    ]  # } sigval_t;


# /* POSIX.1b timers.  */
class _siginfo_t_U_timer(ctypes.Structure):  # struct
    _fields_ = [
        (
            # Timer ID
            # int si_tid;
            "si_tid", ctypes.c_int
        ),
        (
            # Overrun count
            # int si_overrun;
            "si_overrun", ctypes.c_int
        ),
        (
            # Signal value
            # sigval_t si_sigval;
            "si_sigval", sigval_t
        )
    ]  # } _timer;


# /* POSIX.1b signals.  */
class _siginfo_t_U_rt(ctypes.Structure):  # struct
    _fields_ = [
        (
            # Sending process ID
            # __pid_t si_pid;
            "si_pid", ctypes.c_int
        ),
        (
            # Real user ID of sending process
            # __uid_t si_uid;
            "si_uid", ctypes.c_uint
        ),
        (
            # Signal value
            # sigval_t si_sigval;
            "si_sigval", sigval_t
        )
    ]  # } _rt;


# /* SIGCHLD.  */
class _siginfo_t_U_sigchld(ctypes.Structure):  # struct
    _fields_ = [
        (
            # Which child
            # __pid_t si_pid;
            "si_pid", ctypes.c_int
        ),
        (
            # Real user ID of sending process
            # __uid_t si_uid;
            "si_uid", ctypes.c_uint
        ),
        (
            # Exit value or signal
            # int si_status;
            "si_status", ctypes.c_int
        ),
        (
            # __sigchld_clock_t si_utime;
            "si_utime", ctypes.c_long
        ),
        (
            # __sigchld_clock_t si_stime;
            "si_stime", ctypes.c_long
        )
    ]  # } _sigchld;


# /* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
class _siginfo_t_U_sigfault(ctypes.Structure):  # struct
    _fields_ = [
        (
            # Faulting insn/memory ref
            # void *si_addr;
            "si_addr", ctypes.c_void_p
        ),
        (
            # Valid LSB of the reported address
            # short int si_addr_lsb;
            "si_addr_lsb", ctypes.c_short
        )
    ]  # } _sigfault;


# /* SIGPOLL.  */
class _siginfo_t_U_sigpoll(ctypes.Structure):  # struct
    _fields_ = [
        (
            # Band event for SIGPOLL
            # long int si_band;
            "si_band", ctypes.c_long
        ),
        (
            # int si_fd;
            "si_fd", ctypes.c_int
        )
    ]  # } _sigpoll;


# /* SIGSYS.  */
class _siginfo_t_U_sigsys(ctypes.Structure):  # struct
    _fields_ = [
        ("_call_addr", ctypes.c_void_p
         ),  # void *_call_addr;   /* Calling user insn.  */
        (
            "_syscall", ctypes.c_int
        ),  # int _syscall;       /* Triggering system call number.  */
        ("_arch", ctypes.c_uint
         )  # unsigned int _arch; /* AUDIT_ARCH_* of syscall.  */
    ]  # } _sigsys;


class _siginfo_t_U(ctypes.Union):  # union
    _fields_ = [
        ("_pad",
         ctypes.c_int * _SI_PAD_SIZE),  # int _pad[__SI_PAD_SIZE];

        # /* kill().  */
        ("_kill", _siginfo_t_U_kill),  # struct

        # __pid_t si_pid;     /* Sending process ID.  */
        # __uid_t si_uid;     /* Real user ID of sending process.  */
        # } _kill;

        # /* POSIX.1b timers.  */
        ("_timer", _siginfo_t_U_timer),  # struct

        # int si_tid;         /* Timer ID.  */
        # int si_overrun;     /* Overrun count.  */
        # sigval_t si_sigval; /* Signal value.  */
        # } _timer;

        # /* POSIX.1b signals.  */
        ("_rt", _siginfo_t_U_rt),  # struct

        # __pid_t si_pid;     /* Sending process ID.  */
        # __uid_t si_uid;     /* Real user ID of sending process.  */
        # sigval_t si_sigval; /* Signal value.  */
        # } _rt;

        # /* SIGCHLD.  */
        ("_sigchld", _siginfo_t_U_sigchld),  # struct

        # __pid_t si_pid;     /* Which child.  */
        # __uid_t si_uid;     /* Real user ID of sending process.  */
        # int si_status;      /* Exit value or signal.  */
        # __sigchld_clock_t si_utime;
        # __sigchld_clock_t si_stime;
        # } _sigchld;

        # /* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
        ("_sigfault", _siginfo_t_U_sigfault),  # struct

        # void *si_addr;      /* Faulting insn/memory ref.  */
        # short int si_addr_lsb;      /* Valid LSB of the reported address.  */
        # } _sigfault;

        # /* SIGPOLL.  */
        ("_sigpoll", _siginfo_t_U_sigpoll),  # struct

        # long int si_band;   /* Band event for SIGPOLL.  */
        # int si_fd;
        # } _sigpoll;

        # /* SIGSYS.  */
        ("_sigsys", _siginfo_t_U_sigpoll)  # struct

        # void *_call_addr;   /* Calling user insn.  */
        # int _syscall;       /* Triggering system call number.  */
        # unsigned int _arch; /* AUDIT_ARCH_* of syscall.  */
        # } _sigsys;
    ]  # } _sifields;


class siginfo_t(ctypes.Structure):  # typedef struct
    _fields_ = [
        (
            # Signal number
            # int si_signo;
            "si_signo", ctypes.c_int
        ),
        (
            # If non-zero, an errno value associated with
            # int si_errno;
            "si_errno", ctypes.c_int
        ),
        (
            # Signal code - this signal, as defined in <errno.h>
            # int si_code;
            "si_code", ctypes.c_int
        ),
        (
            # Union
            "_sifields", _siginfo_t_U
        )

        # int _pad[__SI_PAD_SIZE];
        #
        # /* kill().  */
        # struct

        # __pid_t si_pid;     /* Sending process ID.  */
        # __uid_t si_uid;     /* Real user ID of sending process.  */
        # } _kill;
        #
        # /* POSIX.1b timers.  */
        # struct

        # int si_tid;         /* Timer ID.  */
        # int si_overrun;     /* Overrun count.  */
        # sigval_t si_sigval; /* Signal value.  */
        # } _timer;
        #
        # /* POSIX.1b signals.  */
        # struct

        # __pid_t si_pid;     /* Sending process ID.  */
        # __uid_t si_uid;     /* Real user ID of sending process.  */
        # sigval_t si_sigval; /* Signal value.  */
        # } _rt;
        #
        # /* SIGCHLD.  */
        # struct

        # __pid_t si_pid;     /* Which child.  */
        # __uid_t si_uid;     /* Real user ID of sending process.  */
        # int si_status;      /* Exit value or signal.  */
        # __sigchld_clock_t si_utime;
        # __sigchld_clock_t si_stime;
        # } _sigchld;
        #
        # /* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
        # struct

        # void *si_addr;      /* Faulting insn/memory ref.  */
        # short int si_addr_lsb;      /* Valid LSB of the reported address.  */
        # } _sigfault;
        #
        # /* SIGPOLL.  */
        # struct

        # long int si_band;   /* Band event for SIGPOLL.  */
        # int si_fd;
        # } _sigpoll;
        #
        # /* SIGSYS.  */
        # struct

        # void *_call_addr;   /* Calling user insn.  */
        # int _syscall;       /* Triggering system call number.  */
        # unsigned int _arch; /* AUDIT_ARCH_* of syscall.  */
        # } _sigsys;
        # } _sifields;
    ]  # } siginfo_t __SI_ALIGNMENT;


# xsave related.


class ymmh_struct(ctypes.Structure):  # struct ymmh_struct {
    _fields_ = [
        # u32 ymmh_space[64];
        ("ymmh_space", 64 * ctypes.c_uint)
    ]  # } __packed;


class xsave_hdr_struct(ctypes.Structure):  # struct xsave_hdr_struct {
    _fields_ = [
        # u64 xstate_bv;
        ("xstate_bv", ctypes.c_ulonglong),
        # u64 reserved1[2];
        ("reserved1", ctypes.c_ulonglong * 2),
        # u64 reserved2[5];
        ("reserved2", ctypes.c_ulonglong * 5)
    ]  # } __packed;


class i387_fxsave_struct(ctypes.Structure):  # struct i387_fxsave_struct {
    _fields_ = [
        (
            # Control Word
            # u16 cwd;
            "cwd", ctypes.c_ushort
        ),
        (
            # Status Word
            # u16 swd;
            "swd", ctypes.c_ushort
        ),
        (
            # Tag Word
            # u16 twd;
            "twd", ctypes.c_ushort
        ),
        (
            # Last Instruction Opcode
            # u16 fop;
            "fop", ctypes.c_ushort
        ),
        # union {
        # struct {
        (
            # Instruction Pointer
            # u64 rip;
            "rip", ctypes.c_ulonglong
        ),
        (
            # Data Pointer
            # u64 rdp;
            "rdp", ctypes.c_ulonglong
        ),

        # struct {
        # u32             fip; /* FPU IP Offset                   */
        # u32             fcs; /* FPU IP Selector                 */
        # u32             foo; /* FPU Operand Offset              */
        # u32             fos; /* FPU Operand Selector            */

        (
            # MXCSR Register State
            # u32 mxcsr;
            "mxcsr", ctypes.c_uint
        ),
        (
            # MXCSR Mask
            # u32 mxcsr_mask;
            "mxcsr_mask", ctypes.c_uint
        ),
        # 8*16 bytes for each FP-reg = 128 bytes
        (
            # u32 st_space[32];
            "st_space", ctypes.c_uint * 32
        ),
        # 16*16 bytes for each XMM-reg = 256 bytes
        (
            # u32 xmm_space[64];
            "xmm_space", ctypes.c_uint * 64
        ),
        (
            # u32 padding[12];
            "padding", ctypes.c_uint * 12
        ),
        # union {
        (
            # u32 padding1[12];
            "padding1", ctypes.c_uint * 12
        )
        # u32                     sw_reserved[12];
    ]  # } __aligned(16);


class elf_xsave_struct(ctypes.Structure):  # struct xsave_struct {
    _fields_ = [
        # struct i387_fxsave_struct i387;
        ("i387", i387_fxsave_struct),
        # struct xsave_hdr_struct xsave_hdr;
        ("xsave_hdr", xsave_hdr_struct),
        # struct ymmh_struct              ymmh;
        ("ymmh", ymmh_struct)
    ]  # } __aligned(FP_MIN_ALIGN_BYTES) __packed;
