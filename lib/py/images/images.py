#!/bin/env python

# This file contains methods to deal with criu images.
#
# According to http://criu.org/Images, criu images can be described
# with such IOW:
#
# IMAGE_FILE ::= MAGIC { ENTRY }
# ENTRY      ::= SIZE PAYLOAD [ EXTRA ]
# PAYLOAD    ::= "message encoded in ProtocolBuffer format"
# EXTRA      ::= "arbitrary blob, depends on the PAYLOAD contents"
#
# MAGIC      ::= "32 bit integer"
# SIZE       ::= "32 bit integer, equals the PAYLOAD length"
#
# Images v1.1 NOTE: MAGIC now consist of 2 32 bit integers, first one is
#	MAGIC_COMMON or MAGIC_SERVICE and the second one is same as MAGIC
#	in images V1.0. We don't keep "first" magic in json images.
#
# In order to convert images to human-readable format, we use dict(json).
# Using json not only allows us to easily read\write images, but also
# to use a great variety of tools out there to manipulate them.
# It also allows us to clearly describe criu images structure.
#
# Using dict(json) format, criu images can be described like:
#
# {
#	'magic' : 'FOO',
#	'entries' : [
#		entry,
#		...
#	]
# }
#
# Entry, in its turn, could be described as:
#
# {
#	pb_msg,
#	'extra' : extra_msg
# }
#
import io
import google
import struct
import os
import sys
import json
import pb2dict
import array

import magic
from pb import *

#
# Predefined hardcoded constants
sizeof_u16 = 2
sizeof_u32 = 4
sizeof_u64 = 8

# A helper for rounding
def round_up(x,y):
	return (((x - 1) | (y - 1)) + 1)

class MagicException(Exception):
	def __init__(self, magic):
		self.magic = magic

# Generic class to handle loading/dumping criu images entries from/to bin
# format to/from dict(json).
class entry_handler:
	"""
	Generic class to handle loading/dumping criu images
	entries from/to bin format to/from dict(json).
	"""
	def __init__(self, payload, extra_handler=None):
		"""
		Sets payload class and extra handler class.
		"""
		self.payload		= payload
		self.extra_handler	= extra_handler

	def load(self, f, pretty = False, no_payload = False):
		"""
		Convert criu image entries from binary format to dict(json).
		Takes a file-like object and returnes a list with entries in
		dict(json) format.
		"""
		entries = []

		while True:
			entry = {}

			# Read payload
			pb = self.payload()
			buf = f.read(4)
			if buf == '':
				break
			size, = struct.unpack('i', buf)
			pb.ParseFromString(f.read(size))
			entry = pb2dict.pb2dict(pb, pretty)

			# Read extra
			if self.extra_handler:
				if no_payload:
					def human_readable(num):
						for unit in ['','K','M','G','T','P','E','Z']:
							if num < 1024.0:
								if int(num) == num:
									return "%d%sB" % (num, unit)
								else:
									return "%.1f%sB" % (num, unit)
							num /= 1024.0
						return "%.1fYB" % num

					pl_size = self.extra_handler.skip(f, pb)
					entry['extra'] = '... <%s>' % human_readable(pl_size)
				else:
					entry['extra'] = self.extra_handler.load(f, pb)

			entries.append(entry)

		return entries

	def loads(self, s, pretty = False):
		"""
		Same as load(), but takes a string as an argument.
		"""
		f = io.BytesIO(s)
		return self.load(f, pretty)

	def dump(self, entries, f):
		"""
		Convert criu image entries from dict(json) format to binary.
		Takes a list of entries and a file-like object to write entries
		in binary format to.
		"""
		for entry in entries:
			extra = entry.pop('extra', None)

			# Write payload
			pb = self.payload()
			pb2dict.dict2pb(entry, pb)
			pb_str = pb.SerializeToString()
			size = len(pb_str)
			f.write(struct.pack('i', size))
			f.write(pb_str)

			# Write extra
			if self.extra_handler and extra:
				self.extra_handler.dump(extra, f, pb)

	def dumps(self, entries):
		"""
		Same as dump(), but doesn't take file-like object and just
		returns a string.
		"""
		f = io.BytesIO('')
		self.dump(entries, f)
		return f.read()

	def count(self, f):
		"""
		Counts the number of top-level object in the image file
		"""
		entries = 0

		while True:
			buf = f.read(4)
			if buf == '':
				break
			size, = struct.unpack('i', buf)
			f.seek(size, 1)
			entries += 1

		return entries

# Special handler for pagemap.img
class pagemap_handler:
	"""
	Special entry handler for pagemap.img, which is unique in a way
	that it has a header of pagemap_head type followed by entries
	of pagemap_entry type.
	"""
	def load(self, f, pretty = False, no_payload = False):
		entries = []

		pb = pagemap_head()
		while True:
			buf = f.read(4)
			if buf == '':
				break
			size, = struct.unpack('i', buf)
			pb.ParseFromString(f.read(size))
			entries.append(pb2dict.pb2dict(pb, pretty))

			pb = pagemap_entry()

		return entries

	def loads(self, s, pretty = False):
		f = io.BytesIO(s)
		return self.load(f, pretty)

	def dump(self, entries, f):
		pb = pagemap_head()
		for item in entries:
			pb2dict.dict2pb(item, pb)
			pb_str = pb.SerializeToString()
			size = len(pb_str)
			f.write(struct.pack('i', size))
			f.write(pb_str)

			pb = pagemap_entry()

	def dumps(self, entries):
		f = io.BytesIO('')
		self.dump(entries, f)
		return f.read()

	def count(self, f):
		return entry_handler(None).count(f) - 1


# In following extra handlers we use base64 encoding
# to store binary data. Even though, the nature
# of base64 is that it increases the total size,
# it doesn't really matter, because our images
# do not store big amounts of binary data. They
# are negligible comparing to pages size.
class pipes_data_extra_handler:
	def load(self, f, pload):
		size = pload.bytes
		data = f.read(size)
		return data.encode('base64')

	def dump(self, extra, f, pload):
		data = extra.decode('base64')
		f.write(data)

	def skip(self, f, pload):
		f.seek(pload.bytes, os.SEEK_CUR)
		return pload.bytes

class sk_queues_extra_handler:
	def load(self, f, pload):
		size = pload.length
		data = f.read(size)
		return data.encode('base64')

	def dump(self, extra, f, pb):
		data = extra.decode('base64')
		f.write(data)

	def skip(self, f, pload):
		f.seek(pload.length, os.SEEK_CUR)
		return pload.length

class ghost_file_extra_handler:
	def load(self, f, pb):
		data = f.read()
		return data.encode('base64')

	def dump(self, extra, f, pb):
		data = extra.decode('base64')
		f.write(data)

	def skip(self, f, pb):
		p = f.tell()
		f.seek(0, os.SEEK_END)
		return f.tell() - p

class tcp_stream_extra_handler:
	def load(self, f, pb):
		d = {}

		inq	= f.read(pb.inq_len)
		outq	= f.read(pb.outq_len)

		d['inq']	= inq.encode('base64')
		d['outq']	= outq.encode('base64')

		return d

	def dump(self, extra, f, pb):
		inq	= extra['inq'].decode('base64')
		outq	= extra['outq'].decode('base64')

		f.write(inq)
		f.write(outq)

	def skip(self, f, pb):
		f.seek(0, os.SEEK_END)
		return pb.inq_len + pb.outq_len

class ipc_sem_set_handler:
	def load(self, f, pb):
		entry = pb2dict.pb2dict(pb)
		size = sizeof_u16 * entry['nsems']
		rounded = round_up(size, sizeof_u64)
		s = array.array('H')
		if s.itemsize != sizeof_u16:
			raise Exception("Array size mismatch")
		s.fromstring(f.read(size))
		f.seek(rounded - size, 1)
		return s.tolist()

	def dump(self, extra, f, pb):
		entry = pb2dict.pb2dict(pb)
		size = sizeof_u16 * entry['nsems']
		rounded = round_up(size, sizeof_u64)
		s = array.array('H')
		if s.itemsize != sizeof_u16:
			raise Exception("Array size mismatch")
		s.fromlist(extra)
		if len(s) != entry['nsems']:
			raise Exception("Number of semaphores mismatch")
		f.write(s.tostring())
		f.write('\0' * (rounded - size))

	def skip(self, f, pb):
		entry = pb2dict.pb2dict(pb)
		size = sizeof_u16 * entry['nsems']
		f.seek(round_up(size, sizeof_u64), os.SEEK_CUR)
		return size

class ipc_msg_queue_handler:
	def load(self, f, pb):
		entry = pb2dict.pb2dict(pb)
		messages = []
		for x in range (0, entry['qnum']):
			buf = f.read(4)
			if buf == '':
				break
			size, = struct.unpack('i', buf)
			msg = ipc_msg()
			msg.ParseFromString(f.read(size))
			rounded = round_up(msg.msize, sizeof_u64)
			data = f.read(msg.msize)
			f.seek(rounded - msg.msize, 1)
			messages.append(pb2dict.pb2dict(msg))
			messages.append(data.encode('base64'))
		return messages

	def dump(self, extra, f, pb):
		entry = pb2dict.pb2dict(pb)
		for i in range (0, len(extra), 2):
			msg = ipc_msg()
			pb2dict.dict2pb(extra[i], msg)
			msg_str = msg.SerializeToString()
			size = len(msg_str)
			f.write(struct.pack('i', size))
			f.write(msg_str)
			rounded = round_up(msg.msize, sizeof_u64)
			data = extra[i + 1].decode('base64')
			f.write(data[:msg.msize])
			f.write('\0' * (rounded - msg.msize))

	def skip(self, f, pb):
		entry = pb2dict.pb2dict(pb)
		pl_len = 0
		for x in range (0, entry['qnum']):
			buf = f.read(4)
			if buf == '':
				break
			size, = struct.unpack('i', buf)
			msg = ipc_msg()
			msg.ParseFromString(f.read(size))
			rounded = round_up(msg.msize, sizeof_u64)
			f.seek(rounded, os.SEEK_CUR)
			pl_len += size + msg.msize

		return pl_len

class ipc_shm_handler:
	def load(self, f, pb):
		entry = pb2dict.pb2dict(pb)
		size = entry['size']
		data = f.read(size)
		rounded = round_up(size, sizeof_u32)
		f.seek(rounded - size, 1)
		return data.encode('base64')

	def dump(self, extra, f, pb):
		entry = pb2dict.pb2dict(pb)
		size = entry['size']
		data = extra.decode('base64')
		rounded = round_up(size, sizeof_u32)
		f.write(data[:size])
		f.write('\0' * (rounded - size))

	def skip(self, f, pb):
		entry = pb2dict.pb2dict(pb)
		size = entry['size']
		rounded = round_up(size, sizeof_u32)
		f.seek(rounded, os.SEEK_CUR)
		return size


handlers = {
	'INVENTORY'		: entry_handler(inventory_entry),
	'CORE'			: entry_handler(core_entry),
	'IDS'			: entry_handler(task_kobj_ids_entry),
	'CREDS'			: entry_handler(creds_entry),
	'UTSNS'			: entry_handler(utsns_entry),
	'IPC_VAR'		: entry_handler(ipc_var_entry),
	'FS'			: entry_handler(fs_entry),
	'GHOST_FILE'		: entry_handler(ghost_file_entry, ghost_file_extra_handler()),
	'MM'			: entry_handler(mm_entry),
	'CGROUP'		: entry_handler(cgroup_entry),
	'TCP_STREAM'		: entry_handler(tcp_stream_entry, tcp_stream_extra_handler()),
	'STATS'			: entry_handler(stats_entry),
	'PAGEMAP'		: pagemap_handler(), # Special one
	'PSTREE'		: entry_handler(pstree_entry),
	'REG_FILES'		: entry_handler(reg_file_entry),
	'NS_FILES'		: entry_handler(ns_file_entry),
	'EVENTFD_FILE'		: entry_handler(eventfd_file_entry),
	'EVENTPOLL_FILE'	: entry_handler(eventpoll_file_entry),
	'EVENTPOLL_TFD'		: entry_handler(eventpoll_tfd_entry),
	'SIGNALFD'		: entry_handler(signalfd_entry),
	'TIMERFD'		: entry_handler(timerfd_entry),
	'INOTIFY_FILE'		: entry_handler(inotify_file_entry),
	'INOTIFY_WD'		: entry_handler(inotify_wd_entry),
	'FANOTIFY_FILE'		: entry_handler(fanotify_file_entry),
	'FANOTIFY_MARK'		: entry_handler(fanotify_mark_entry),
	'VMAS'			: entry_handler(vma_entry),
	'PIPES'			: entry_handler(pipe_entry),
	'FIFO'			: entry_handler(fifo_entry),
	'SIGACT'		: entry_handler(sa_entry),
	'NETLINK_SK'		: entry_handler(netlink_sk_entry),
	'REMAP_FPATH'		: entry_handler(remap_file_path_entry),
	'MNTS'			: entry_handler(mnt_entry),
	'TTY_FILES'		: entry_handler(tty_file_entry),
	'TTY_INFO'		: entry_handler(tty_info_entry),
	'TTY_DATA'		: entry_handler(tty_data_entry),
	'RLIMIT'		: entry_handler(rlimit_entry),
	'TUNFILE'		: entry_handler(tunfile_entry),
	'EXT_FILES'		: entry_handler(ext_file_entry),
	'IRMAP_CACHE'		: entry_handler(irmap_cache_entry),
	'FILE_LOCKS'		: entry_handler(file_lock_entry),
	'FDINFO'		: entry_handler(fdinfo_entry),
	'UNIXSK'		: entry_handler(unix_sk_entry),
	'INETSK'		: entry_handler(inet_sk_entry),
	'PACKETSK'		: entry_handler(packet_sock_entry),
	'ITIMERS'		: entry_handler(itimer_entry),
	'POSIX_TIMERS'		: entry_handler(posix_timer_entry),
	'NETDEV'		: entry_handler(net_device_entry),
	'PIPES_DATA'		: entry_handler(pipe_data_entry, pipes_data_extra_handler()),
	'FIFO_DATA'		: entry_handler(pipe_data_entry, pipes_data_extra_handler()),
	'SK_QUEUES'		: entry_handler(sk_packet_entry, sk_queues_extra_handler()),
	'IPCNS_SHM'		: entry_handler(ipc_shm_entry, ipc_shm_handler()),
	'IPCNS_SEM'		: entry_handler(ipc_sem_entry, ipc_sem_set_handler()),
	'IPCNS_MSG'		: entry_handler(ipc_msg_entry, ipc_msg_queue_handler()),
	'NETNS'			: entry_handler(netns_entry),
	'USERNS'		: entry_handler(userns_entry),
	'SECCOMP'		: entry_handler(seccomp_entry),
	}

def __rhandler(f):
	# Images v1.1 NOTE: First read "first" magic.
	img_magic, = struct.unpack('i', f.read(4))
	if img_magic in (magic.by_name['IMG_COMMON'], magic.by_name['IMG_SERVICE']):
		img_magic, = struct.unpack('i', f.read(4))

	try:
		m = magic.by_val[img_magic]
	except:
		raise MagicException(img_magic)

	try:
		handler = handlers[m]
	except:
		raise Exception("No handler found for image with magic " + m)

	return m, handler

def load(f, pretty = False, no_payload = False):
	"""
	Convert criu image from binary format to dict(json).
	Takes a file-like object to read criu image from.
	Returns criu image in dict(json) format.
	"""
	image = {}

	m, handler = __rhandler(f)

	image['magic'] = m
	image['entries'] = handler.load(f, pretty, no_payload)

	return image

def info(f):
	res = {}

	m, handler = __rhandler(f)

	res['magic'] = m
	res['count'] = handler.count(f)

	return res

def loads(s, pretty = False):
	"""
	Same as load(), but takes a string.
	"""
	f = io.BytesIO(s)
	return load(f, pretty)

def dump(img, f):
	"""
	Convert criu image from dict(json) format to binary.
	Takes an image in dict(json) format and file-like
	object to write to.
	"""
	m = img['magic']
	magic_val = magic.by_name[img['magic']]

	# Images v1.1 NOTE: use "second" magic to identify what "first"
	# should be written.
	if m != 'INVENTORY':
		if m in ('STATS', 'IRMAP_CACHE'):
			f.write(struct.pack('i', magic.by_name['IMG_SERVICE']))
		else:
			f.write(struct.pack('i', magic.by_name['IMG_COMMON']))

	f.write(struct.pack('i', magic_val))

	try:
		handler = handlers[m]
	except:
		raise Exception("No handler found for image with such magic")

	handler.dump(img['entries'], f)

def dumps(img):
	"""
	Same as dump(), but takes only an image and returns
	a string.
	"""
	f = io.BytesIO('')
	dump(img, f)
	return f.getvalue()
