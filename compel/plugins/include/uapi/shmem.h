#ifndef __COMPEL_PLUGIN_SHMEM_H__
#define __COMPEL_PLUGIN_SHMEM_H__

/*
 * Creates local shmem mapping and announces it
 * to the peer. Peer can later "receive" one. The
 * local area should be munmap()-ed at the end.
 */
extern void *shmem_create(unsigned long size);
/*
 * "Receives" shmem from peer and maps it. The
 * locally mapped area should be munmap()-ed at
 * the end
 */
extern void *shmem_receive(unsigned long *size);

#endif /* __COMPEL_PLUGIN_SHMEM_H__ */
