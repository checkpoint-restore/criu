# Functions and classes for creating core dump from criu images.
# Code is inspired by outdated google coredumper(RIP) [1] and
# fs/binfmt_elf.h from Linux kernel [2].
#
# [1] https://code.google.com/p/google-coredumper/
#     probably already dead, so consider trying:
#     https://github.com/efiop/google-coredumper/
# [2] https://www.kernel.org/
#
# On my x86_64 systems with fresh kernel ~3.17 core dump looks like:
#
#	1) Elf file header;
#	2) PT_NOTE program header describing notes section;
#	3) PT_LOAD program headers for (almost?) each vma;
#	4) NT_PRPSINFO note with elf_prpsinfo inside;
#	5) An array of notes for each thread of the process:
#		NT_PRSTATUS note with elf_prstatus inside;
#		NT_FPREGSET note with elf_fpregset inside;
#		NT_X86_XSTATE note with x86 extended state using xsave;
#		NT_SIGINFO note with siginfo_t inside;
#	6) NT_AUXV note with auxv;
#	7) NT_FILE note with mapped files;
#	8) VMAs themselves;
#
# Or, you can represent it in less details as:
#	1) Elf file header;
#	2) Program table;
#	3) Notes;
#	4) VMAs contents;
#
import io
import elf
import ctypes
from pycriu import images

# Some memory-related constants
PAGESIZE = 4096
status = {
	"VMA_AREA_NONE"		: 0 << 0,
	"VMA_AREA_REGULAR"	: 1 << 0,
	"VMA_AREA_STACK"	: 1 << 1,
	"VMA_AREA_VSYSCALL"	: 1 << 2,
	"VMA_AREA_VDSO"		: 1 << 3,
	"VMA_FORCE_READ"	: 1 << 4,
	"VMA_AREA_HEAP"		: 1 << 5,
	"VMA_FILE_PRIVATE"	: 1 << 6,
	"VMA_FILE_SHARED"	: 1 << 7,
	"VMA_ANON_SHARED"	: 1 << 8,
	"VMA_ANON_PRIVATE"	: 1 << 9,
	"VMA_AREA_SYSVIPC"	: 1 << 10,
	"VMA_AREA_SOCKET"	: 1 << 11,
	"VMA_AREA_VVAR"		: 1 << 12,
	"VMA_AREA_AIORING"	: 1 << 13,
	"VMA_AREA_UNSUPP"	: 1 << 31
}

prot = {
	"PROT_READ"	: 0x1,
	"PROT_WRITE"	: 0x2,
	"PROT_EXEC"	: 0x4
}

class elf_note:
	nhdr	= None	# Elf_Nhdr;
	owner	= None	# i.e. CORE or LINUX;
	data	= None	# Ctypes structure with note data;


class coredump:
	"""
	A class to keep elf core dump components inside and
	functions to properly write them to file.
	"""
	ehdr	= None	# Elf ehdr;
	phdrs	= []	# Array of Phdrs;
	notes	= []	# Array of elf_notes;
	vmas	= []	# Array of BytesIO with memory content;
			# FIXME keeping all vmas in memory is a bad idea;

	def write(self, f):
		"""
		Write core dump to file f.
		"""
		buf = io.BytesIO()
		buf.write(self.ehdr)

		for phdr in self.phdrs:
			buf.write(phdr)

		for note in self.notes:
			buf.write(note.nhdr)
			buf.write(note.owner)
			buf.write("\0"*(8-len(note.owner)))
			buf.write(note.data)

		offset = ctypes.sizeof(elf.Elf64_Ehdr())
		offset += (len(self.vmas) + 1)*ctypes.sizeof(elf.Elf64_Phdr())

		filesz = 0
		for note in self.notes:
			filesz += ctypes.sizeof(note.nhdr) + ctypes.sizeof(note.data) + 8

		note_align	= PAGESIZE - ((offset + filesz) % PAGESIZE)

		if note_align == PAGESIZE:
			note_align = 0

		if note_align != 0:
			scratch = (ctypes.c_char * note_align)()
			ctypes.memset(ctypes.addressof(scratch), 0, ctypes.sizeof(scratch))
			buf.write(scratch)

		for vma in self.vmas:
			buf.write(vma.data)

		buf.seek(0)
		f.write(buf.read())


class coredump_generator:
	"""
	Generate core dump from criu images.
	"""
	coredumps	= {} # coredumps by pid;

	pstree		= {} # process info by pid;
	cores		= {} # cores by pid;
	mms		= {} # mm by pid;
	reg_files	= None # reg-files;
	pagemaps	= {} # pagemap by pid;

	def _img_open_and_strip(self, name, single = False, pid = None):
		"""
		Load criu image and strip it from magic and redundant list.
		"""
		path = self._imgs_dir + "/" + name
		if pid:
			path += "-"+str(pid)
		path += ".img"

		with open(path) as f:
			img = images.load(f)

		if single:
			return img["entries"][0]
		else:
			return img["entries"]


	def __call__(self, imgs_dir):
		"""
		Parse criu images stored in directory imgs_dir to fill core dumps.
		"""
		self._imgs_dir	= imgs_dir
		pstree		= self._img_open_and_strip("pstree")

		for p in pstree:
			pid = p['pid']

			self.pstree[pid]	= p
			for tid in p['threads']:
				self.cores[tid]	= self._img_open_and_strip("core", True, tid)
			self.mms[pid]		= self._img_open_and_strip("mm", True, pid)
			self.pagemaps[pid]	= self._img_open_and_strip("pagemap", False, pid)

		self.reg_files	= self._img_open_and_strip("reg-files", False)

		for pid in self.pstree:
			self.coredumps[pid] = self._gen_coredump(pid)

		return self.coredumps


	def write(self, coredumps_dir, pid = None):
		"""
		Write core dumpt to cores_dir directory. Specify pid to choose
		core dump of only one process.
		"""
		for p in self.coredumps:
			if pid and p != pid:
				continue
			with open(coredumps_dir+"/"+"core."+str(p), 'w+') as f:
				self.coredumps[p].write(f)

	def _gen_coredump(self, pid):
		"""
		Generate core dump for pid.
		"""
		cd = coredump()

		# Generate everything backwards so it is easier to calculate offset.
		cd.vmas		= self._gen_vmas(pid)
		cd.notes	= self._gen_notes(pid)
		cd.phdrs	= self._gen_phdrs(pid, cd.notes, cd.vmas)
		cd.ehdr		= self._gen_ehdr(pid, cd.phdrs)

		return cd

	def _gen_ehdr(self, pid, phdrs):
		"""
		Generate elf header for process pid with program headers phdrs.
		"""
		ehdr = elf.Elf64_Ehdr()

		ctypes.memset(ctypes.addressof(ehdr), 0, ctypes.sizeof(ehdr))
		ehdr.e_ident[elf.EI_MAG0]	= elf.ELFMAG0
		ehdr.e_ident[elf.EI_MAG1]	= elf.ELFMAG1
		ehdr.e_ident[elf.EI_MAG2]	= elf.ELFMAG2
		ehdr.e_ident[elf.EI_MAG3]	= elf.ELFMAG3
		ehdr.e_ident[elf.EI_CLASS]	= elf.ELFCLASS64
		ehdr.e_ident[elf.EI_DATA]	= elf.ELFDATA2LSB
		ehdr.e_ident[elf.EI_VERSION]	= elf.EV_CURRENT

		ehdr.e_type		= elf.ET_CORE
		ehdr.e_machine		= elf.EM_X86_64
		ehdr.e_version		= elf.EV_CURRENT
		ehdr.e_phoff		= ctypes.sizeof(elf.Elf64_Ehdr())
		ehdr.e_ehsize		= ctypes.sizeof(elf.Elf64_Ehdr())
		ehdr.e_phentsize	= ctypes.sizeof(elf.Elf64_Phdr())
		#FIXME Case len(phdrs) > PN_XNUM should be handled properly.
		# See fs/binfmt_elf.c from linux kernel.
		ehdr.e_phnum	= len(phdrs)

		return ehdr

	def _gen_phdrs(self, pid, notes, vmas):
		"""
		Generate program headers for process pid.
		"""
		phdrs = []

		offset = ctypes.sizeof(elf.Elf64_Ehdr())
		offset += (len(vmas) + 1)*ctypes.sizeof(elf.Elf64_Phdr())

		filesz = 0
		for note in notes:
			filesz += ctypes.sizeof(note.nhdr) + ctypes.sizeof(note.data) + 8

		# PT_NOTE
		phdr = elf.Elf64_Phdr()
		ctypes.memset(ctypes.addressof(phdr), 0, ctypes.sizeof(phdr))
		phdr.p_type	= elf.PT_NOTE
		phdr.p_offset	= offset
		phdr.p_filesz	= filesz

		phdrs.append(phdr)

		note_align	= PAGESIZE - ((offset + filesz) % PAGESIZE)

		if note_align == PAGESIZE:
			note_align = 0

		offset += note_align

		# VMA phdrs

		for vma in vmas:
			offset += filesz
			filesz = vma.filesz
			phdr = elf.Elf64_Phdr()
			ctypes.memset(ctypes.addressof(phdr), 0, ctypes.sizeof(phdr))
			phdr.p_type	= elf.PT_LOAD
			phdr.p_align	= PAGESIZE
			phdr.p_paddr	= 0
			phdr.p_offset	= offset
			phdr.p_vaddr	= vma.start
			phdr.p_memsz	= vma.memsz
			phdr.p_filesz	= vma.filesz
			phdr.p_flags	= vma.flags

			phdrs.append(phdr)

		return phdrs

	def _gen_prpsinfo(self, pid):
		"""
		Generate NT_PRPSINFO note for process pid.
		"""
		pstree	= self.pstree[pid]
		core	= self.cores[pid]

		prpsinfo = elf.elf_prpsinfo()
		ctypes.memset(ctypes.addressof(prpsinfo), 0, ctypes.sizeof(prpsinfo))

		# FIXME TASK_ALIVE means that it is either running or sleeping, need to
		# teach criu to distinguish them.
		TASK_ALIVE	= 0x1
		# XXX A bit of confusion here, as in ps "dead" and "zombie"
		# state are two separate states, and we use TASK_DEAD for zombies.
		TASK_DEAD	= 0x2
		TASK_STOPPED	= 0x3
		if core["tc"]["task_state"] == TASK_ALIVE:
			prpsinfo.pr_state	= 0
		if core["tc"]["task_state"] == TASK_DEAD:
			prpsinfo.pr_state	= 4
		if core["tc"]["task_state"] == TASK_STOPPED:
			prpsinfo.pr_state	= 3
		# Don't even ask me why it is so, just borrowed from linux
		# source and made pr_state match.
		prpsinfo.pr_sname	= '.' if prpsinfo.pr_state > 5 else "RSDTZW"[prpsinfo.pr_state]
		prpsinfo.pr_zomb	= 1 if prpsinfo.pr_state == 4 else 0
		prpsinfo.pr_nice	= core["thread_core"]["sched_prio"] if "sched_prio" in core["thread_core"] else 0
		prpsinfo.pr_flag	= core["tc"]["flags"]
		prpsinfo.pr_uid		= core["thread_core"]["creds"]["uid"]
		prpsinfo.pr_gid		= core["thread_core"]["creds"]["gid"]
		prpsinfo.pr_pid		= pid
		prpsinfo.pr_ppid	= pstree["ppid"]
		prpsinfo.pr_pgrp	= pstree["pgid"]
		prpsinfo.pr_sid		= pstree["sid"]
		prpsinfo.pr_fname	= core["tc"]["comm"]
		prpsinfo.pr_psargs	= self._gen_cmdline(pid)

		nhdr = elf.Elf64_Nhdr()
		nhdr.n_namesz	= 5
		nhdr.n_descsz	= ctypes.sizeof(elf.elf_prpsinfo())
		nhdr.n_type	= elf.NT_PRPSINFO

		note = elf_note()
		note.data	= prpsinfo
		note.owner	= "CORE"
		note.nhdr 	= nhdr

		return note

	def _gen_prstatus(self, pid, tid):
		"""
		Generate NT_PRSTATUS note for thread tid of process pid.
		"""
		core	= self.cores[tid]
		regs	= core["thread_info"]["gpregs"]
		pstree	= self.pstree[pid]

		prstatus = elf.elf_prstatus()

		ctypes.memset(ctypes.addressof(prstatus), 0, ctypes.sizeof(prstatus))

		#FIXME setting only some of the fields for now. Revisit later.
		prstatus.pr_pid		= tid
		prstatus.pr_ppid	= pstree["ppid"]
		prstatus.pr_pgrp	= pstree["pgid"]
		prstatus.pr_sid		= pstree["sid"]

		prstatus.pr_reg.r15		= regs["r15"]
		prstatus.pr_reg.r14		= regs["r14"]
		prstatus.pr_reg.r13		= regs["r13"]
		prstatus.pr_reg.r12		= regs["r12"]
		prstatus.pr_reg.rbp		= regs["bp"]
		prstatus.pr_reg.rbx		= regs["bx"]
		prstatus.pr_reg.r11		= regs["r11"]
		prstatus.pr_reg.r10		= regs["r10"]
		prstatus.pr_reg.r9		= regs["r9"]
		prstatus.pr_reg.r8		= regs["r8"]
		prstatus.pr_reg.rax		= regs["ax"]
		prstatus.pr_reg.rcx		= regs["cx"]
		prstatus.pr_reg.rdx		= regs["dx"]
		prstatus.pr_reg.rsi		= regs["si"]
		prstatus.pr_reg.rdi		= regs["di"]
		prstatus.pr_reg.orig_rax	= regs["orig_ax"]
		prstatus.pr_reg.rip		= regs["ip"]
		prstatus.pr_reg.cs		= regs["cs"]
		prstatus.pr_reg.eflags		= regs["flags"]
		prstatus.pr_reg.rsp		= regs["sp"]
		prstatus.pr_reg.ss		= regs["ss"]
		prstatus.pr_reg.fs_base		= regs["fs_base"]
		prstatus.pr_reg.gs_base		= regs["gs_base"]
		prstatus.pr_reg.ds		= regs["ds"]
		prstatus.pr_reg.es		= regs["es"]
		prstatus.pr_reg.fs		= regs["fs"]
		prstatus.pr_reg.gs		= regs["gs"]

		nhdr = elf.Elf64_Nhdr()
		nhdr.n_namesz	= 5
		nhdr.n_descsz	= ctypes.sizeof(elf.elf_prstatus())
		nhdr.n_type	= elf.NT_PRSTATUS

		note = elf_note()
		note.data	= prstatus
		note.owner	= "CORE"
		note.nhdr 	= nhdr

		return note

	def _gen_fpregset(self, pid, tid):
		"""
		Generate NT_FPREGSET note for thread tid of process pid.
		"""
		core	= self.cores[tid]
		regs	= core["thread_info"]["fpregs"]

		fpregset = elf.elf_fpregset_t()
		ctypes.memset(ctypes.addressof(fpregset), 0, ctypes.sizeof(fpregset))

		fpregset.cwd		= regs["cwd"]
		fpregset.swd		= regs["swd"]
		fpregset.ftw		= regs["twd"]
		fpregset.fop		= regs["fop"]
		fpregset.rip		= regs["rip"]
		fpregset.rdp		= regs["rdp"]
		fpregset.mxcsr		= regs["mxcsr"]
		fpregset.mxcr_mask	= regs["mxcsr_mask"]
		fpregset.st_space	= (ctypes.c_uint * len(regs["st_space"]))(*regs["st_space"])
		fpregset.xmm_space	= (ctypes.c_uint * len(regs["xmm_space"]))(*regs["xmm_space"])
		#fpregset.padding	= regs["padding"] unused

		nhdr = elf.Elf64_Nhdr()
		nhdr.n_namesz	= 5
		nhdr.n_descsz	= ctypes.sizeof(elf.elf_fpregset_t())
		nhdr.n_type	= elf.NT_FPREGSET

		note = elf_note()
		note.data	= fpregset
		note.owner	= "CORE"
		note.nhdr 	= nhdr

		return note

	def _gen_x86_xstate(self, pid, tid):
		"""
		Generate NT_X86_XSTATE note for thread tid of process pid.
		"""
		core	= self.cores[tid]
		fpregs	= core["thread_info"]["fpregs"]

		data = elf.elf_xsave_struct()
		ctypes.memset(ctypes.addressof(data), 0, ctypes.sizeof(data))

		data.i387.cwd		= fpregs["cwd"]
		data.i387.swd		= fpregs["swd"]
		data.i387.twd		= fpregs["twd"]
		data.i387.fop		= fpregs["fop"]
		data.i387.rip		= fpregs["rip"]
		data.i387.rdp		= fpregs["rdp"]
		data.i387.mxcsr		= fpregs["mxcsr"]
		data.i387.mxcsr_mask	= fpregs["mxcsr_mask"]
		data.i387.st_space	= (ctypes.c_uint * len(fpregs["st_space"]))(*fpregs["st_space"])
		data.i387.xmm_space	= (ctypes.c_uint * len(fpregs["xmm_space"]))(*fpregs["xmm_space"])

		if "xsave" in fpregs:
			data.xsave_hdr.xstate_bv = fpregs["xsave"]["xstate_bv"]
			data.ymmh.ymmh_space	= (ctypes.c_uint * len(fpregs["xsave"]["ymmh_space"]))(*fpregs["xsave"]["ymmh_space"])

		nhdr = elf.Elf64_Nhdr()
		nhdr.n_namesz	= 6
		nhdr.n_descsz	= ctypes.sizeof(data)
		nhdr.n_type	= elf.NT_X86_XSTATE

		note = elf_note()
		note.data	= data
		note.owner	= "LINUX"
		note.nhdr 	= nhdr

		return note

	def _gen_siginfo(self, pid, tid):
		"""
		Generate NT_SIGINFO note for thread tid of process pid.
		"""
		siginfo = elf.siginfo_t()
		# FIXME zeroify everything for now
		ctypes.memset(ctypes.addressof(siginfo), 0, ctypes.sizeof(siginfo))

		nhdr = elf.Elf64_Nhdr()
		nhdr.n_namesz	= 5
		nhdr.n_descsz	= ctypes.sizeof(elf.siginfo_t())
		nhdr.n_type	= elf.NT_SIGINFO

		note = elf_note()
		note.data	= siginfo
		note.owner	= "CORE"
		note.nhdr 	= nhdr

		return note

	def _gen_auxv(self, pid):
		"""
		Generate NT_AUXV note for thread tid of process pid.
		"""
		mm = self.mms[pid]
		num_auxv = len(mm["mm_saved_auxv"])/2

		class elf_auxv(ctypes.Structure):
			_fields_ = [("auxv", elf.Elf64_auxv_t*num_auxv)]

		auxv = elf_auxv()
		for i in range(num_auxv):
			auxv.auxv[i].a_type	= mm["mm_saved_auxv"][i]
			auxv.auxv[i].a_val	= mm["mm_saved_auxv"][i+1]

		nhdr = elf.Elf64_Nhdr()
		nhdr.n_namesz	= 5
		nhdr.n_descsz	= ctypes.sizeof(elf_auxv())
		nhdr.n_type	= elf.NT_AUXV

		note = elf_note()
		note.data	= auxv
		note.owner	= "CORE"
		note.nhdr	= nhdr

		return note

	def _gen_files(self, pid):
		"""
		Generate NT_FILE note for process pid.
		"""
		mm = self.mms[pid]

		class mmaped_file_info:
			start		= None
			end		= None
			file_ofs	= None
			name		= None

		infos = []
		for vma in mm["vmas"]:
			if vma["shmid"] == 0:
				# shmid == 0 means that it is not a file
				continue

			shmid	= vma["shmid"]
			size	= vma["end"] - vma["start"]
			off	= vma["pgoff"]/PAGESIZE

			files	= self.reg_files
			fname	= filter(lambda x: x["id"] == shmid, files)[0]["name"]

			info = mmaped_file_info()
			info.start	= vma["start"]
			info.end	= vma["end"]
			info.file_ofs	= off
			info.name	= fname

			infos.append(info)

		# /*
		#  * Format of NT_FILE note:
		#  *
		#  * long count     -- how many files are mapped
		#  * long page_size -- units for file_ofs
		#  * array of [COUNT] elements of
		#  *   long start
		#  *   long end
		#  *   long file_ofs
		#  * followed by COUNT filenames in ASCII: "FILE1" NUL "FILE2" NUL...
		#  */
		fields = []
		fields.append(("count",		ctypes.c_long))
		fields.append(("page_size",	ctypes.c_long))
		for i in range(len(infos)):
			fields.append(("start"+str(i),		ctypes.c_long))
			fields.append(("end"+str(i),		ctypes.c_long))
			fields.append(("file_ofs"+str(i),	ctypes.c_long))
		for i in range(len(infos)):
			fields.append(("name"+str(i),	ctypes.c_char*(len(infos[i].name)+1)))

		class elf_files(ctypes.Structure):
			_fields_ = fields

		data = elf_files()
		data.count	= len(infos)
		data.page_size	= PAGESIZE
		for i in range(len(infos)):
			info = infos[i]
			setattr(data,	"start"+str(i),		info.start)
			setattr(data,	"end"+str(i),		info.end)
			setattr(data,	"file_ofs"+str(i),	info.file_ofs)
			setattr(data,	"name"+str(i),		info.name)

		nhdr = elf.Elf64_Nhdr()

		nhdr.n_namesz	= 5#XXX strlen + 1
		nhdr.n_descsz	= ctypes.sizeof(elf_files())
		nhdr.n_type	= elf.NT_FILE

		note = elf_note()
		note.nhdr	= nhdr
		note.owner	= "CORE"
		note.data	= data

		return note

	def _gen_thread_notes(self, pid, tid):
		notes = []

		notes.append(self._gen_prstatus(pid, tid))
		notes.append(self._gen_fpregset(pid, tid))
		notes.append(self._gen_x86_xstate(pid, tid))
		notes.append(self._gen_siginfo(pid, tid))

		return notes

	def _gen_notes(self, pid):
		"""
		Generate notes for core dump of process pid.
		"""
		notes = []

		notes.append(self._gen_prpsinfo(pid))

		threads = self.pstree[pid]["threads"]

		# Main thread first
		notes += self._gen_thread_notes(pid, pid)

		# Then other threads
		for tid in threads:
			if tid == pid:
				continue

			notes += self._gen_thread_notes(pid, tid)

		notes.append(self._gen_auxv(pid))
		notes.append(self._gen_files(pid))

		return notes

	def _get_page(self, pid, page_no):
		"""
		Try to find memory page page_no in pages.img image for process pid.
		"""
		pagemap = self.pagemaps[pid]

		# First entry is pagemap_head, we will need it later to open
		# proper pages.img.
		pages_id = pagemap[0]["pages_id"]
		off = 0# in pages
		for m in pagemap[1:]:
			found = False
			for i in range(m["nr_pages"]):
				if m["vaddr"] + i*PAGESIZE == page_no*PAGESIZE:
					found = True
					break
				off += 1

			if not found:
				continue

			if "in_parent" in m and m["in_parent"] == True:
				ppid = self.pstree[pid]["ppid"]
				return self._get_page(ppid, page_no)
			else:
				with open(self._imgs_dir+"/"+"pages-"+str(pages_id)+".img") as f:
					f.seek(off*PAGESIZE)
					return f.read(PAGESIZE)

		return None

	def _gen_mem_chunk(self, pid, vma, size):
		"""
		Obtain vma contents for process pid.
		"""
		f = None

		if size == 0:
			return ""

		if vma["status"] & status["VMA_AREA_VVAR"]:
			#FIXME this is what gdb does, as vvar vma
			# is not readable from userspace?
			return "\0"*size
		elif vma["status"] & status["VMA_AREA_VSYSCALL"]:
			#FIXME need to dump it with criu or read from
			# current process.
			return "\0"*size

		if vma["status"] & status["VMA_FILE_SHARED"] or \
		   vma["status"] & status["VMA_FILE_PRIVATE"]:
			# Open file before iterating vma pages
			shmid	= vma["shmid"]
			off	= vma["pgoff"]

			files	= self.reg_files
			fname	= filter(lambda x: x["id"] == shmid, files)[0]["name"]

			f = open(fname)
			f.seek(off)

		start	= vma["start"]
		end	= vma["start"] + size

		# Split requested memory chunk into pages, so it could be
		# pictured as:
		#
		# "----" -- part of page with memory outside of our vma;
		# "XXXX" -- memory from our vma;
		#
		#  Start page     Pages in the middle        End page
		# [-----XXXXX]...[XXXXXXXXXX][XXXXXXXXXX]...[XXX-------]
		#
		# Each page could be found in pages.img or in a standalone
		# file described by shmid field in vma entry and
		# corresponding entry in reg-files.img.
		# For VMA_FILE_PRIVATE vma, unchanged pages are taken from
		# a file, and changed ones -- from pages.img.
		# Finally, if no page is found neither in pages.img nor
		# in file, hole in inserted -- a page filled with zeroes.
		start_page	= start/PAGESIZE
		end_page	= end/PAGESIZE

		buf = ""
		for page_no in range(start_page, end_page+1):
			page = None

			# Search for needed page in pages.img and reg-files.img
			# and choose appropriate.
			page_mem = self._get_page(pid, page_no)

			if f != None:
				page = f.read(PAGESIZE)

			if page_mem != None:
				# Page from pages.img has higher priority
				# than one from maped file on disk.
				page = page_mem

			if page == None:
				# Hole
				page = PAGESIZE*"\0"

			# If it is a start or end page, we need to read
			# only part of it.
			if page_no == start_page:
				n_skip = start - page_no*PAGESIZE
				if start_page == end_page:
					n_read = size
				else:
					n_read = PAGESIZE - n_skip
			elif page_no == end_page:
				n_skip = 0
				n_read = end - page_no*PAGESIZE
			else:
				n_skip = 0
				n_read = PAGESIZE

			buf += page[n_skip : n_skip + n_read]

		# Don't forget to close file.
		if f != None:
			f.close()

		return buf

	def _gen_cmdline(self, pid):
		"""
		Generate full command with arguments.
		"""
		mm = self.mms[pid]

		vma = {}
		vma["start"]	= mm["mm_arg_start"]
		vma["end"]	= mm["mm_arg_end"]
		# Dummy flags and status.
		vma["flags"]	= 0
		vma["status"]	= 0
		size		= vma["end"] - vma["start"]

		chunk = self._gen_mem_chunk(pid, vma, size)

		# Replace all '\0's with spaces.
		return chunk.replace('\0', ' ')

	def _get_vma_dump_size(self, vma):
		"""
		Calculate amount of vma to put into core dump.
		"""
		if vma["status"] & status["VMA_AREA_VVAR"] or \
		   vma["status"] & status["VMA_AREA_VSYSCALL"] or \
		   vma["status"] & status["VMA_AREA_VDSO"]:
			size = vma["end"] - vma["start"]
		elif vma["prot"] == 0:
			size = 0
		elif vma["prot"] & prot["PROT_READ"] and \
		     vma["prot"] & prot["PROT_EXEC"]:
			size = PAGESIZE
		elif vma["status"] & status["VMA_ANON_SHARED"] or \
		     vma["status"] & status["VMA_FILE_SHARED"] or \
		     vma["status"] & status["VMA_ANON_PRIVATE"] or \
		     vma["status"] & status["VMA_FILE_PRIVATE"]:
			size = vma["end"] - vma["start"]
		else:
			size = 0

		return size

	def _get_vma_flags(self, vma):
		"""
		Convert vma flags int elf flags.
		"""
		flags = 0

		if vma['prot'] & prot["PROT_READ"]:
			flags = flags | elf.PF_R

		if vma['prot'] & prot["PROT_WRITE"]:
			flags = flags | elf.PF_W

		if vma['prot'] & prot["PROT_EXEC"]:
			flags = flags | elf.PF_X

		return flags

	def _gen_vmas(self, pid):
		"""
		Generate vma contents for core dump for process pid.
		"""
		mm = self.mms[pid]

		class vma_class:
			data	= None
			filesz	= None
			memsz	= None
			flags	= None
			start	= None

		vmas = []
		for vma in mm["vmas"]:
			size = self._get_vma_dump_size(vma)

			chunk = self._gen_mem_chunk(pid, vma, size)

			v = vma_class()
			v.filesz	= self._get_vma_dump_size(vma)
			v.data		= self._gen_mem_chunk(pid, vma, v.filesz)
			v.memsz		= vma["end"] - vma["start"]
			v.start		= vma["start"]
			v.flags		= self._get_vma_flags(vma)

			vmas.append(v)

		return vmas
