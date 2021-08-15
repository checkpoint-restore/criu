import os
import tempfile
import subprocess


class criu_config:
    @staticmethod
    def run(action,
            args,
            criu_bin,
            fault=None,
            strace=[],
            preexec=None,
            nowait=False):

        config_path = tempfile.mktemp(".conf", "criu-%s-" % action)
        with open(config_path, "w") as config_fd:
            for arg in args:
                if arg.startswith("--"):
                    config_fd.write("\n")
                    arg = arg.strip("-")
                config_fd.write("%s " % arg)

        env = dict(
            os.environ,
            ASAN_OPTIONS="log_path=asan.log:disable_coredump=0:detect_leaks=0"
        )

        if fault:
            print("Forcing %s fault" % fault)
            env['CRIU_FAULT'] = fault

        cr = subprocess.Popen(
            strace +
            [criu_bin, action, "--no-default-config", "--config", config_path],
            env=env,
            close_fds=False,
            preexec_fn=preexec
        )
        if nowait:
            return cr
        return cr.wait()
