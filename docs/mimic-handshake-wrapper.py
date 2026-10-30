#!/usr/bin/python3
"""Server workaround for Hysteria's zero-interval Mimic filters on ens3:8443.

Install separately from /usr/sbin/mimic and set this instance's mimic.path.
All other commands, filters, and options pass through unchanged. exec preserves
Mimic's PID and signal handling under Hysteria's process supervision.
"""

import os
import sys


def rewrite_filter(value):
    fields = value.split(",")
    address = fields[0]
    if address.startswith("local=") and address.rsplit(":", 1)[-1] == "8443":
        fields[1:] = [
            "handshake=2:3" if field == "handshake=0:3" else field
            for field in fields[1:]
        ]
    return ",".join(fields)


def rewrite(arguments):
    arguments = list(arguments)
    if arguments[:2] != ["run", "ens3"]:
        return arguments
    for index, argument in enumerate(arguments):
        if index > 0 and arguments[index - 1] in ("-f", "--filter"):
            arguments[index] = rewrite_filter(argument)
        elif argument.startswith("--filter="):
            arguments[index] = "--filter=" + rewrite_filter(argument[len("--filter="):])
    return arguments


if __name__ == "__main__":
    executable = "/usr/sbin/mimic"
    os.execv(executable, [executable, *rewrite(sys.argv[1:])])
