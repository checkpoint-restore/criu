import argparse
import os

import criu_coredump


def coredump(opts):
    generator = criu_coredump.coredump_generator()
    cores = generator(os.path.realpath(opts['in']))
    for pid in cores:
        if opts['pid'] and pid != opts['pid']:
            continue
        with open(os.path.realpath(opts['out']) + "/core." + str(pid), 'wb+') as f:
            cores[pid].write(f)


def main():
    desc = 'CRIU core dump'
    parser = argparse.ArgumentParser(description=desc,
                                     formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-i',
                        '--in',
                        default='.',
                        help='directory where to get images from')
    parser.add_argument('-p',
                        '--pid',
                        type=int,
                        help='generate coredump for specific pid(all pids py default)')
    parser.add_argument('-o',
                        '--out',
                        default='.',
                        help='directory to write coredumps to')

    opts = vars(parser.parse_args())

    coredump(opts)


if __name__ == '__main__':
    main()
