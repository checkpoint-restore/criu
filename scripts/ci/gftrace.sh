#!/bin/bash

# Original script was written by Pavel Tikhomirov and slightly modified by me

if [ "$#" -lt 1 ]; then
	echo "usage: $0 <kernel_function> [<kernel_function> ...]"
	echo "kernel_function - functions to trace (separated by spaces), all should be in #available_filter_functions list"
	exit 1
fi

KFUNCS="${@:1}"

for KFUNC in $KFUNCS
do
	# Check that kernel function is traceable
	if ! cat /sys/kernel/debug/tracing/available_filter_functions \
			| grep "\<$KFUNC\>" >/dev/null; then
		echo "There is no traceable kfunc \"$KFUNC\" may be you mean:"
		cat /sys/kernel/debug/tracing/available_filter_functions | grep $KFUNC
		exit 1
	fi
done

# Disable previous tracing
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo nop > /sys/kernel/debug/tracing/current_tracer
echo 0 > /sys/kernel/debug/tracing/max_graph_depth
echo 0 > /sys/kernel/debug/tracing/events/enable

# Setup tracing all call graphs for a KFUNCS kernel functions
echo "$KFUNCS" > /sys/kernel/debug/tracing/set_graph_function

echo "Will graph trace:"
cat /sys/kernel/debug/tracing/set_graph_function

echo function_graph > /sys/kernel/debug/tracing/current_tracer

# Setup some useful tracing options:
echo funcgraph-tail > /sys/kernel/debug/tracing/trace_options 2>/dev/null
echo funcgraph-abstime > /sys/kernel/debug/tracing/trace_options
echo nofuncgraph-irqs > /sys/kernel/debug/tracing/trace_options

# Set max recursion to 5
echo 5 > /sys/kernel/debug/tracing/max_graph_depth

finish_trace() {
	echo 0 > /sys/kernel/debug/tracing/tracing_on
	cat /sys/kernel/debug/tracing/trace > trace
	echo "hint: cat ./trace | less"

	echo nop > /sys/kernel/debug/tracing/current_tracer
	echo 0 > /sys/kernel/debug/tracing/max_graph_depth
	if [ -f "/sys/kernel/debug/tracing/events/probe/enable" ]; then
		echo 0 > /sys/kernel/debug/tracing/events/enable
	fi
	exit 0
}

trap 'finish_trace' SIGINT

if [ -f "/sys/kernel/debug/tracing/events/probe/enable" ]; then
	# Enable probes
	echo 1 > /sys/kernel/debug/tracing/events/probe/enable
fi

# Enable ftrace
echo 1 > /sys/kernel/debug/tracing/tracing_on

echo "Enter something (or ctrl+c) to stop tracing"
read < endtracefifo
finish_trace