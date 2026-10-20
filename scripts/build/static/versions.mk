# Pinned versions of the static dependencies.
#
# For each dependency NAME:
#   NAME_VERSION   pinned version
#   NAME_URL       source tarball (recursive, so it follows NAME_VERSION)
#   NAME_SHA256    checksum of the tarball
#   NAME_GIT       upstream repository, used by `make check-updates`
#   NAME_TAG_SED   sed expression that turns a release tag into a version
#
# Use `./update.sh NAME VERSION` to update a dependency; it rewrites the
# version and checksum here.

empty :=
space := $(empty) $(empty)
# $(call major-minor,1.2.3) -> 1.2
major-minor = $(subst $(space),.,$(wordlist 1,2,$(subst ., ,$(1))))

LIBNL_VERSION        := 3.12.0
LIBNL_URL             = https://github.com/thom311/libnl/releases/download/libnl$(subst .,_,$(LIBNL_VERSION))/libnl-$(LIBNL_VERSION).tar.gz
LIBNL_SHA256         := fc51ca7196f1a3f5fdf6ffd3864b50f4f9c02333be28be4eeca057e103c0dd18
LIBNL_GIT            := https://github.com/thom311/libnl.git
LIBNL_TAG_SED        := s/^libnl([0-9]+)_([0-9]+)_([0-9]+)$$/\1.\2.\3/p

LIBNET_VERSION       := 1.3
LIBNET_URL            = https://github.com/libnet/libnet/releases/download/v$(LIBNET_VERSION)/libnet-$(LIBNET_VERSION).tar.gz
LIBNET_SHA256        := ad1e2dd9b500c58ee462acd839d0a0ea9a2b9248a1287840bc601e774fb6b28f
LIBNET_GIT           := https://github.com/libnet/libnet.git
LIBNET_TAG_SED       := s/^v([0-9.]+)$$/\1/p

LIBCAP_VERSION       := 2.78
LIBCAP_URL            = https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-$(LIBCAP_VERSION).tar.gz
LIBCAP_SHA256        := 2a2c705e382c413643a458b837575c0eb0989477ab6fb99c87adbe9a259612ad
LIBCAP_GIT           := https://git.kernel.org/pub/scm/libs/libcap/libcap.git
LIBCAP_TAG_SED       := s/^libcap-([0-9]+\.[0-9]+)$$/\1/p

LZ4_VERSION          := 1.10.0
LZ4_URL               = https://github.com/lz4/lz4/releases/download/v$(LZ4_VERSION)/lz4-$(LZ4_VERSION).tar.gz
LZ4_SHA256           := 537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b
LZ4_GIT              := https://github.com/lz4/lz4.git
LZ4_TAG_SED          := s/^v([0-9.]+)$$/\1/p

PROTOBUF_C_VERSION   := 1.5.2
PROTOBUF_C_URL        = https://github.com/protobuf-c/protobuf-c/releases/download/v$(PROTOBUF_C_VERSION)/protobuf-c-$(PROTOBUF_C_VERSION).tar.gz
PROTOBUF_C_SHA256    := e2c86271873a79c92b58fef7ebf8de1aa0df4738347a8bd5d4e65a80a16d0d24
PROTOBUF_C_GIT       := https://github.com/protobuf-c/protobuf-c.git
PROTOBUF_C_TAG_SED   := s/^v([0-9.]+)$$/\1/p

LIBMNL_VERSION       := 1.0.5
LIBMNL_URL            = https://netfilter.org/projects/libmnl/files/libmnl-$(LIBMNL_VERSION).tar.bz2
LIBMNL_SHA256        := 274b9b919ef3152bfb3da3a13c950dd60d6e2bcd54230ffeca298d03b40d0525
LIBMNL_GIT           := https://git.netfilter.org/libmnl
LIBMNL_TAG_SED       := s/^libmnl-([0-9.]+)$$/\1/p

LIBNFTNL_VERSION     := 1.3.2
LIBNFTNL_URL          = https://netfilter.org/projects/libnftnl/files/libnftnl-$(LIBNFTNL_VERSION).tar.xz
LIBNFTNL_SHA256      := c97abc3409f8fa396b4462b2bb7f147a3a47a4ddc97cfa0b2f18890c9cfde8b0
LIBNFTNL_GIT         := https://git.netfilter.org/libnftnl
LIBNFTNL_TAG_SED     := s/^libnftnl-([0-9.]+)$$/\1/p

LIBNFTABLES_VERSION  := 1.1.7
LIBNFTABLES_URL       = https://netfilter.org/projects/nftables/files/nftables-$(LIBNFTABLES_VERSION).tar.xz
LIBNFTABLES_SHA256   := a6fbf060d8d4fff001517a2b94f356bb4366bfbf0ba366366f9d27cc38caa58f
LIBNFTABLES_GIT      := https://git.netfilter.org/nftables
LIBNFTABLES_TAG_SED  := s/^v([0-9.]+)$$/\1/p

UTIL_LINUX_VERSION   := 2.42.4
UTIL_LINUX_URL        = https://www.kernel.org/pub/linux/utils/util-linux/v$(call major-minor,$(UTIL_LINUX_VERSION))/util-linux-$(UTIL_LINUX_VERSION).tar.gz
UTIL_LINUX_SHA256    := af3241e7776964dcb6bb9a811ca7b0d93000b563e2ae2a8df8f80a7cd6e04d56
UTIL_LINUX_GIT       := https://github.com/util-linux/util-linux.git
UTIL_LINUX_TAG_SED   := s/^v([0-9.]+)$$/\1/p

PCRE2_VERSION        := 10.49
PCRE2_URL             = https://github.com/PCRE2Project/pcre2/releases/download/pcre2-$(PCRE2_VERSION)/pcre2-$(PCRE2_VERSION).tar.gz
PCRE2_SHA256         := 929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae
PCRE2_GIT            := https://github.com/PCRE2Project/pcre2.git
PCRE2_TAG_SED        := s/^pcre2-([0-9.]+)$$/\1/p

# libsepol and libselinux are released together; keep their versions equal.
LIBSEPOL_VERSION     := 3.11
LIBSEPOL_URL          = https://github.com/SELinuxProject/selinux/releases/download/$(LIBSEPOL_VERSION)/libsepol-$(LIBSEPOL_VERSION).tar.gz
LIBSEPOL_SHA256      := 79f3d2c88f44b7eb5cf54d9792e03232297e17f97a179163f2750099a00f164d
LIBSEPOL_GIT         := https://github.com/SELinuxProject/selinux.git
LIBSEPOL_TAG_SED     := s/^([0-9]+\.[0-9.]+)$$/\1/p

LIBSELINUX_VERSION   := 3.11
LIBSELINUX_URL        = https://github.com/SELinuxProject/selinux/releases/download/$(LIBSELINUX_VERSION)/libselinux-$(LIBSELINUX_VERSION).tar.gz
LIBSELINUX_SHA256    := 73d419c6e20e874adaa4019372cbd097eecf4d276e13f27ec5e67d35c0bd203c
LIBSELINUX_GIT       := https://github.com/SELinuxProject/selinux.git
LIBSELINUX_TAG_SED   := s/^([0-9]+\.[0-9.]+)$$/\1/p
