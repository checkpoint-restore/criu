#!/usr/bin/env python3

import os
import sys

EXPECTED_ACTIONS = [
    'pre-dump',
    'network-lock',
    'post-dump',
    'pre-restore',
    'setup-namespaces',
    'post-setup-namespaces',
    'post-restore',
    'network-unlock',
    'pre-resume',
    'post-resume',
]

errors = []
actions_called = []
actions_called_file = os.path.join(os.path.dirname(__file__), 'actions_called.txt')

with open(actions_called_file) as f:
    for index, line in enumerate(f):
        parts = line.strip().split()
        parts += ['EMPTY'] * (3 - len(parts))
        action_hook, image_dir, pid = parts

        if action_hook == 'EMPTY':
            raise ValueError("Error in test: bogus actions line")

        expected_action = EXPECTED_ACTIONS[index] if index < len(EXPECTED_ACTIONS) else None
        if action_hook != expected_action:
            raise ValueError(f"Invalid action: {action_hook} != {expected_action}")

        if image_dir == 'EMPTY':
            errors.append(f'Action {action_hook} misses CRTOOLS_IMAGE_DIR')

        if action_hook != 'pre-restore':
            if pid == 'EMPTY':
                errors.append(f'Action {action_hook} misses CRTOOLS_INIT_PID')
            elif not pid.isdigit() or int(pid) == 0:
                errors.append(f'Action {action_hook} PID is not a valid number ({pid})')

        actions_called.append(action_hook)

if actions_called != EXPECTED_ACTIONS:
    errors.append(f'Not all actions called: {actions_called!r}')

if errors:
    print('\n'.join(errors))
    sys.exit(1)

print('Check Actions PASS')
