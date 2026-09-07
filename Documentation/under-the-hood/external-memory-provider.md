# External memory provider

The optional external memory provider supplies image file descriptors during
dump and restore, and backing file descriptors for memory objects during
restore. It is enabled by passing a connected Unix `SOCK_SEQPACKET`
descriptor as the inherited-FD resource
`extmem-provider`, for example `--inherit-fd fd[4]:extmem-provider`.
CRIU resolves the descriptor from its inherited-FD table when the provider
session starts.

CRIU sends one protobuf `extmem_req` packet per request and receives one
protobuf `extmem_resp` packet. A successful `OPEN_IMAGE`, `GET_VMA`, or
`GET_SHARED` response carries exactly one descriptor with `SCM_RIGHTS`.
`images/extmem.proto` uses proto2.
Each request and response must fit in an 8 KiB packet. CRIU rejects a response
with any unexpected ancillary data.
`OPEN_IMAGE` names only a relative CRIU image path and its open flags; the
provider never receives an image-directory or checkpoint-root descriptor.
During dump, a successful `OPEN_IMAGE` response supplies a writable image
target. CRIU writes the normal image format to that descriptor. During
restore, the same operation supplies a readable image source.

The restore operation sequence is `INIT`, zero or more image and memory
requests, `WAIT_READY`, then `COMMIT` on successful restore or `ABORT` on
failure. After accepting `INIT`, a provider must support `WAIT_READY`;
`-ENOTSUP` for that operation is a protocol error. A successful `WAIT_READY`
response tells CRIU that the provider has finished populating the returned
objects. CRIU then applies the saved memfd seals, and runs `ACT_PRE_RESUME`
only after that.
The order is `WAIT_READY` -> `apply_memfd_seals()` -> `ACT_PRE_RESUME` ->
task resume. Private mappings are identified by
`(pid, vma_id, vaddr, length)` and shared objects by
`(shmid, length)`. A successful memory request returns a file descriptor for
one complete object; CRIU maps it directly and does not copy page-image
contents into it. Each restoring task offers its private VMAs to the provider
before it enters PIE; PIE then moves provider-backed mappings to their final
addresses. Private hugetlb VMAs use the same early request and premap path.
`vma_id` is the restore-side VMA ordinal used
with the other fields to identify a private mapping; it is not a durable
checkpoint ID.

The dump operation sequence is `INIT`, zero or more image requests, then
`COMMIT` after all image data has been flushed and `ACT_POST_DUMP` has
succeeded. Failures before `COMMIT` send `ABORT`. A `COMMIT` failure is
reported as a dump failure. `WAIT_READY` is not used for dump
output; `COMMIT` must not succeed until the provider has retained the image
data and generated any provider-specific plan needed for a later restore.

For an unsupported image the provider returns `-ENOTSUP`; CRIU then uses its
local path for that image. During dump, this fallback is possible only before
CRIU has written to that image's provider descriptor. Once CRIU has started
writing that image, a write or non-`ENOTSUP` provider error aborts the dump
rather than reopening it locally. Other images may still use the local path.
While premapping a private VMA, CRIU requests it from the provider. If
`GET_VMA` returns `-ENOTSUP`, CRIU leaves the VMA unchanged and uses its normal
restore path. If `GET_SHARED` returns
`-ENOTSUP`, CRIU uses its normal shmem or memfd restore path. Other provider
errors abort the restore. Forced-local images are always
opened by CRIU and are not offered to the provider. The dump-side image path is
enabled only for a normal dump, not for pre-dump.

For provider-backed private VMAs and shmem mappings, CRIU maps the returned
file descriptor directly and does not require a particular file type or
validate its backing size first. The provider must return an FD that can back
the requested mapping. A provider-supplied descriptor for a checkpointed memfd
must allow CRIU to apply the saved seals after `WAIT_READY`.
For a huge-page mapping, the descriptor must use the matching huge-page size.

For `OPEN_IMAGE`, CRIU passes the returned descriptor through its existing
image reader or writer.
