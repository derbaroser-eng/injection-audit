"""Background tasks for the demo corpus."""
import os
import sys


def render(template_dir):
    path = os.path.join("/srv/tpl", template_dir)
    return open(path).read()


def publish(user_input):
    payload = render(user_input)
    os.system("grep -R 'x' " + payload)
    os.environ["LAST"] = user_input
    return os.environ.get("LAST")


def cli():
    publish(sys.argv[1])
