#!/usr/bin/python3
import sys
import re

re_file = r'^diff --git a/(\S\S*)\s.*$'
re_line = r'^@@ -(\d\d*)\D.*@@.*$'

if __name__ == '__main__':
    if len(sys.argv) != 1 and len(sys.argv) != 2:
        print(f'usage: {sys.argv[0]} <path/to/file>')
        print(f'usage: <command> | {sys.argv[0]}')
        exit(1)

    input_file = sys.stdin.fileno()
    if len(sys.argv) == 2:
        input_file = sys.argv[1]

    with open(input_file, 'r') as fi:
        file_name = None
        line_number = None
        for line in fi:
            file_matches = re.findall(re_file, line)
            if len(file_matches) == 1:
                file_name = file_matches[0]
                continue

            if file_name is None:
                continue

            line_matches = re.findall(re_line, line)
            if len(line_matches) == 1:
                line_number = int(line_matches[0]) + 3
                print(f'::warning file={file_name},line={line_number}::clang-format: Possible coding style problem (https://github.com/checkpoint-restore/criu/blob/criu-dev/CONTRIBUTING.md#automatic-tools-to-fix-coding-style)')
