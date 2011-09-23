
#define FDINFO_MAGIC	0x01010101

struct fdinfo_entry {
	__u8	type;
	__u8	len;
	__u16	flags;
	__u32	pos;
	__u64	addr;
};

#define FDINFO_FD	1
#define FDINFO_MAP	2

#define PAGES_MAGIC	0x20202020

#define SHMEM_MAGIC	0x03300330

struct shmem_entry {
	__u64	start;
	__u64	end;
	__u64	shmid;
};

#define PSTREE_MAGIC	0x40044004

struct pstree_entry {
	__u32	pid;
	__u32	nr_children;
};

#define PIPES_MAGIC	0x05055050

struct pipes_entry {
	__u32	fd;
	__u32	pipeid;
	__u32	flags;
	__u32	bytes;
};
