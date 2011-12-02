#!/bin/bash
#
# parse command line flags of the form --foo=bar and print out an eval-able line

name=$0

function die() {
	echo "$name: $*" >&2
	exit 1
}

# eat our flags first
while : ; do
	flag=$1
	shift || break
	case $flag in
		--flags-req=*)	# req'd flags
			oIFS="$IFS" IFS=","
			vars_req=(${flag#*=})
			IFS="$oIFS"
			;;
		--flags-opt=*)	# optional flags
			oIFS="$IFS" IFS=","
			vars_opt=(${flag#*=})
			IFS="$oIFS"
			;;
		--name=*)	# name to report errors as
			name=${flag#*=}
			;;
		--flags-only)	# report only flags
			show_flags=true show_args=false
			;;
		--no-flags)	# report only remaining args
			show_flags=false show_args=true
			;;
		--)		# end of our flags; external flags follow
			break
			;;
	esac
done

# consume external flags
while : ; do
	flag=$1
	shift || break
	case $flag in
		--*=*)
			;;
		--)		# end of external flags; uninterpreted arguments follow
			break
			;;
		*)		# pass unrecognized arguments through
			args="$args '$flag'"
			continue
			;;
	esac

	flagname=${flag%%=*}
	flagname=${flagname#--}
	flagval=${flag#*=}

	# check if this flag is declared
	case " ${vars_req[*]} ${vars_opt[*]} " in
		*" $flagname "*)
			;;
		*)		# pass unrecognized flags through
			args="$args '$flag'"
			continue
			;;
	esac

	eval $flagname=\"$flagval\"
done

# check that we have all required flags
for var in ${vars_req[@]}; do
	${!var+true} die "--$var is required"
done

# now print 'em out
if ${show_flags:-true}; then
	for var in ${vars_req[@]} ${vars_opt[@]}; do
		# only print those that are set (even to an empty string)
		${!var+echo $var="'${!var}'"}
	done
fi
if ${show_args:-true}; then
	for arg in "$@"; do	# get quotes right
		args="$args '$arg'"
	done
	echo "set -- $args"
fi
