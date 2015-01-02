#!/bin/bash

#
# A convenience shell script to call criu for checkpointing and restoring
# a Docker container.
#
# This script saves the user from having to remember all the command
# line options, some of which are very long.  Note that once Docker
# has native support for checkpoint and restore, there will no longer
# be a need for this particular shell script.
#

set -o errexit
set -o nounset
set -o pipefail

#
# These can be set in the environment to override their defaults.
# Note that while the default value of CRIU_IMG_DIR in this script
# is a directory in DOCKER_HOME, it doesn't have to be tied to
# DOCKER_HOME.  For example, it can be /var/spool/criu_img.
#
: ${DOCKER_HOME=/var/lib/docker}
: ${DOCKER_BINARY=docker}
: ${CRIU_IMG_DIR=${DOCKER_HOME}/criu_img}
: ${CRIU_BINARY=criu}
: ${DOCKERINIT_BINARY=}

declare -A BIND_MOUNT
BIND_MOUNT[/etc/resolv.conf]=.ResolvConfPath
BIND_MOUNT[/etc/hosts]=.HostsPath
BIND_MOUNT[/etc/hostname]=.HostnamePath
MOUNT_MAP_ARGS=()

#
# The default mode is non-verbose, printing only a short message
# saying if the comand succeeded or failed.  For the verbose mode,
# we could have used set -o xtrace but this option would have
# generated excessive output suitable for debugging, not normal
# usage.  So we set ${ECHO} to echo in the verbose mode to print
# selected messages.
#
VERBOSE=""
ECHO=":"
CMD=""
PGNAME=$(basename "$0")

usage() {
	local rv=0

	if [[ -n "${1-}" ]]; then
		rv=1
		echo -e "${PGNAME}: $1\n" >&2
	fi

	cat <<EOF
Usage:
	${PGNAME} -c|-r [-hv] [<container_id>]
	-c, --checkpoint	checkpoint container
	-h, --help		print help message
	-r, --restore		restore container
	-v, --verbose		enable verbose mode

Environment:
	DOCKER_HOME		(default ${DOCKER_HOME})
	CRIU_IMG_DIR		(default ${CRIU_IMG_DIR})
	DOCKER_BINARY		(default ${DOCKER_BINARY})
	DOCKERINIT_BINARY	(default \${DOCKER_HOME}/init/dockerinit-<version>-dev)
	CRIU_BINARY		(default ${CRIU_BINARY})
EOF
	exit ${rv}
}

#
# If the user has not specified a bind mount file for the container's
# /.dockerinit, try to determine it from the Docker version.
#
find_dockerinit() {
	local v

	if [[ -z "${DOCKERINIT_BINARY}" ]]; then
		v=$("${DOCKER_BINARY}" --version | sed -e 's/.*version \(.*\),.*/\1/')
		DOCKERINIT_BINARY="${DOCKER_HOME}/init/dockerinit-${v}"
	elif [[ "${DOCKERINIT_BINARY}" != /* ]]; then
		DOCKERINIT_BINARY="${DOCKER_HOME}/init/${DOCKERINIT_BINARY}"
	fi

	if [[ ! -x "${DOCKERINIT_BINARY}" ]]; then
		echo "${DOCKERINIT_BINARY} does not exist"
		exit 1
	fi

	BIND_MOUNT[/.dockerinit]="${DOCKERINIT_BINARY}"
}

parse_args() {
	local args
	local flags

	args=$(getopt --options 'chrv' \
		--longoptions 'checkpoint help restore verbose' -- "$@")
	[[ $? == 0 ]] || usage
	eval set -- "${args}"

	while :; do
		arg="${1}"
		shift
		case "${arg}" in
		-c|--checkpoint) CMD="dump" ;;
		-h|--help) usage ;;
		-r|--restore) CMD="restore" ;;
		-v|--verbose) VERBOSE="-v"; ECHO="echo" ;;
		--) break ;;
		*) usage "internal error parsing arguments!" ;;
		esac
	done

	[[ "${CMD}" == "" ]] && usage "need either -c or -r"
	[[ $# -gt 1 ]] && usage "$# too many arguments"

	# if no container id in args, prompt the user
	if [[ $# -eq 1 ]]; then
		CID="$1"
	else
		if [[ "${CMD}" == "dump" ]]; then
			flags=""
		else
			# we need -a only for restore
			flags="-a"
		fi
		"${DOCKER_BINARY}" ps ${flags}
		read -rp $'\nContainer ID: ' CID
	fi
}

execute() {
	# since commands are pretty long and can wrap around
	# several lines, print a blank line to make it visually
	# easier to see
	${ECHO} -e "\n$*"
	"$@"
}

init_container_vars() {
	local d

	CID=$(get_container_conf .Id)

	d=$("${DOCKER_BINARY}" info 2> /dev/null | awk '/Storage Driver:/ { print $3 }')
	if [[ "${d}" == "vfs" ]]; then
		CONTAINER_ROOT_DIR="${DOCKER_HOME}/${d}/dir/${CID}"
	else
		CONTAINER_ROOT_DIR="${DOCKER_HOME}/${d}/mnt/${CID}"
	fi
	CONTAINER_IMG_DIR="${CRIU_IMG_DIR}/${CID}"
}

get_container_conf() {
	local val

	val=$("${DOCKER_BINARY}" inspect --format "{{$1}}" "${CID}")
	[[ "${val}" == "" ]] && exit 1
	echo "${val/<no value>/}"
}

setup_mount_map() {
	local key

	if [[ "$1" == "dump" ]]; then
		for key in "${!BIND_MOUNT[@]}"; do
			MOUNT_MAP_ARGS+=(--ext-mount-map "${key}:${key}")
		done
	else
		for key in "${!BIND_MOUNT[@]}"; do
			if [[ "${key}" == "/.dockerinit" ]]; then
				MOUNT_MAP_ARGS+=("--ext-mount-map" "${key}:${BIND_MOUNT[$key]}")
			else
				MOUNT_MAP_ARGS+=("--ext-mount-map" "${key}:$(get_container_conf "${BIND_MOUNT[$key]}")")
			fi
		done
	fi
}

fs_mounted() {
	grep -wq "$1" /proc/mounts
}


#
# Pretty print the mount command in verbose mode by putting each branch
# pathname on a single line for easier visual inspection.
#
pp_mount() {
	${ECHO} -e "\nmount -t $1 -o"
	${ECHO} "${2}" | tr ':' '\n'
	${ECHO} none
	${ECHO} "${3}"
}

#
# Reconstruct the AUFS filesystem from information in CRIU's dump log.
# The dump log has a series of branch entries for each process in the
# entire process tree in the following form:
#
# (00.014075) /sys/fs/aufs/si_f598876b0855b883/br0 : /var/lib/docker/aufs/diff/<ID>
#
# Note that this script assumes that all processes in the process
# tree have the same AUFS filesystem.  This assumption is fairly
# safe for typical Docker containers.
#
setup_aufs() {
	local logf="${CONTAINER_IMG_DIR}/dump.log"
	local tmpf="${CONTAINER_IMG_DIR}/aufs.br"
	local br
	local branches

	# create a temporary file with branches listed in
	# ascending order (line 1 is branch 0)
	awk '/aufs.si_/ { print $2, $4 }' "${logf}" | sort | uniq | \
		awk '{ print $2 }' > "${tmpf}"

	# nothing to do if filesystem already mounted
	fs_mounted "${CONTAINER_ROOT_DIR}" && return

	# construct the mount option string from branches
	branches=""
	while read br; do
		branches+="${branches:+:}${br}"
	done < "${tmpf}"

	# mount the container's filesystem
	pp_mount "aufs" "${branches}" "${CONTAINER_ROOT_DIR}"
	mount -t aufs -o br="${branches}" none "${CONTAINER_ROOT_DIR}"
	rm -f "${tmpf}"
}

#
# Reconstruct the UnionFS filesystem from information in CRIU's dump log.
# The dump log has the mountinfo root entry for the filesystem.  The
# options field contains the list of directories that make up the UnionFS.
#
# Note that this script assumes that all processes in the process
# tree have the same UnionFS filesystem.  This assumption is fairly
# safe for typical Docker containers.
#
# XXX If /dev/null was manually created by Docker (i.e., it's not in
#     a branch), create it.  Although this has worked so far, it needs
#     a deeper look as I am not sure if /dev/null should be created as
#     a regular file to be the target of a bind mount or created as a
#     device file by mknod.
#
setup_unionfs() {
	local logf="${CONTAINER_IMG_DIR}/dump.log"
	local dirs

	# nothing to do if filesystem already mounted
	fs_mounted "${CONTAINER_ROOT_DIR}" && return

	dirs=$(sed -n -e 's/.*type.*dirs=/dirs=/p' "${logf}")
	[[ "${dirs}" = "" ]] && echo "do not have branch information" && exit 1

	# mount the container's filesystem
	pp_mount "unionfs" "${dirs}" "${CONTAINER_ROOT_DIR}"
	mount -t unionfs -o "${dirs}" none "${CONTAINER_ROOT_DIR}"

	# see comment at the beginning of the function
	if [[ ! -e "${CONTAINER_ROOT_DIR}/dev/null" ]]; then
		execute touch "${CONTAINER_ROOT_DIR}/dev/null"
	fi
}

prep_dump() {
	local pid

	pid=$(get_container_conf .State.Pid)

	# docker returns 0 for containers it thinks have exited
	# (i.e., dumping a restored container again)
	if [[ ${pid} -eq 0 ]]; then
		read -p "Process ID: " pid
	fi

	# remove files previously created by criu but not others files (if any)
	mkdir -p "${CONTAINER_IMG_DIR}"
	rm -f "${CONTAINER_IMG_DIR}"/*.{img,log,pid} "${CONTAINER_IMG_DIR}"/stats-restore

	CMD_ARGS=("-t" "${pid}")

	# we need --root only for aufs to compensate for the
	# erroneous information in /proc/<pid>/map_files
	if [[ "${CONTAINER_ROOT_DIR}" == *aufs* ]]; then
		CMD_ARGS+=("--root" "${CONTAINER_ROOT_DIR}")
	fi
}

prep_restore() {
	local aufs_pattern='/sys/fs/aufs/si_'
	local unionfs_pattern='type.*source.*options.*dirs='

	# set up aufs and unionfs mounts if they're not already set up
	if grep -q "${aufs_pattern}" "${CONTAINER_IMG_DIR}/dump.log"; then
		setup_aufs
	elif grep -q "${unionfs_pattern}" "${CONTAINER_IMG_DIR}/dump.log"; then
		setup_unionfs
	fi

	# criu requires this (due to container using pivot_root)
	if ! grep -q "${CONTAINER_ROOT_DIR}" /proc/mounts; then
		execute mount --rbind "${CONTAINER_ROOT_DIR}" "${CONTAINER_ROOT_DIR}"
		MOUNTED=1
	else
		MOUNTED=0
	fi

	CMD_ARGS=("-d" "--root" "${CONTAINER_ROOT_DIR}" "--pidfile" "${CONTAINER_IMG_DIR}/restore.pid")
}

#
# Since this function produces output string (either in the
# verbose mode or from ${CRIU_BINARY}), we set the return value
# in parameter 1.
#
run_criu() {
	local -a common_args=("-v4" "-D" "${CONTAINER_IMG_DIR}" \
			"-o" "${CMD}.log" \
			"--manage-cgroups" \
			"--evasive-devices")

	setup_mount_map "${CMD}"
	common_args+=("${MOUNT_MAP_ARGS[@]}")

	# we do not want to exit if there's an error
	execute "${CRIU_BINARY}" "${CMD}" "${common_args[@]}" "${CMD_ARGS[@]}"
}

wrap_up() {
	local logf="${CONTAINER_IMG_DIR}/${CMD}.log"
	local pidf="${CONTAINER_IMG_DIR}/restore.pid"

	if [[ $1 -eq 0 ]]; then
		${ECHO} -e "\n"
		echo "${CMD} successful"
	else
		${ECHO} -e "\n"
		echo "${CMD} failed"
	fi

	if [[ "${VERBOSE}" == "-v" && -e "${logf}" ]]; then
		if ! grep "finished successfully" "${logf}"; then
			grep Error "${logf}"
		fi
	fi

	if [[ "${CMD}" == "restore" ]]; then
		if [[ ${MOUNTED} -eq 1 ]]; then
			execute umount "${CONTAINER_ROOT_DIR}"
		fi

		if [[ -e "${pidf}" ]]; then
			${ECHO} -e "\n$(ps -f -p "$(cat "${pidf}")" --no-headers)"
		fi
	fi
}

main() {
	local rv=0

	parse_args "$@"
	find_dockerinit
	init_container_vars

	${ECHO} "docker binary: ${DOCKER_BINARY}"
	${ECHO} "dockerinit binary: ${DOCKERINIT_BINARY}"
	${ECHO} "criu binary: ${CRIU_BINARY}"
	${ECHO} "image directory: ${CONTAINER_IMG_DIR}"
	${ECHO} "container root directory: ${CONTAINER_ROOT_DIR}"

	if [[ "${CMD}" == "dump" ]]; then
		prep_dump
	else
		prep_restore
	fi

	run_criu || rv=$?
	wrap_up ${rv}
	exit ${rv}
}

main "$@"
