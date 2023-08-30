#!/bin/bash

# This script fetches .clang-format from the Linux kernel
# and slightly adapts it for CRIU.

URL="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/.clang-format?h=v5.13"

curl -s "${URL}" | sed -e "
	s,^\( *\)#\([A-Z]\),\1\2,g;
	s,ControlStatements,ControlStatementsExceptForEachMacros,g;
	s,ColumnLimit: 80,ColumnLimit: 0,g;
	s,Intended for clang-format >= 4,Intended for clang-format >= 11,g;
	s,ForEachMacros:,ForEachMacros:\n  - 'for_each_bit',g;
	s,ForEachMacros:,ForEachMacros:\n  - 'for_each_pstree_item',g;
	s,\(AlignTrailingComments:.*\)$,\1\nAlignConsecutiveMacros: true,g;
	s,AlignTrailingComments: false,AlignTrailingComments: true,g;
	s,\(IndentCaseLabels: false\),\1\nIndentGotoLabels: false,g;
"  > .clang-format
