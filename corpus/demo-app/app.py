"""Demo service used as the audit corpus: deliberately mixed safe and unsafe."""
import os
import subprocess
import sys

from flask import request


def build_greeting(name):
    import shlex
    return f"echo {shlex.quote(name)}"


def handle_ping():
    host = request.args.get("host")
    subprocess.run(f"ping -c 1 {host}", shell=True)
    return "ok"


def status():
    subprocess.run(["git", "status", "--porcelain"])
    return "done"


def deploy(branch):
    cmd = "git checkout %s && make" % branch
    subprocess.Popen(cmd, shell=True)


if __name__ == "__main__":
    deploy(os.getenv("BRANCH"))
    handle_ping()
