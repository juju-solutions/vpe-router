
import subprocess


class NetNS(object):
    def __init__(self, name):
        pass

    @classmethod
    def create(cls, name):
        # @TODO: Need to check if namespace exists already
        try:
            ip('netns', 'add', name)
        except Exception as e:
            raise Exception('could not create net namespace: %s' % e)

        return cls(name)

    def up(self, iface, cidr):
        self.exec('ip', 'link', 'set', 'dev', iface, 'up')
        self.exec('ip', 'address', 'add', cidr, 'dev', iface)

    def add_iface(self, iface):
        ip('link', 'set', 'dev', iface, 'netns', self.name)

    def exec(self, *cmd):
        ip(*['netns', 'exec', self.name] + cmd)


def ip(*args):
    try:
        largs = list(args)
        _run(['ip'] + largs)
    except subprocess.CalledProcessError as e:
        raise Exception('unable to run %s: %s' % (' '.join(['ip'] + args), e))


def _run(cmd, env=None):
    if isinstance(cmd, str):
        cmd = cmd.split() if ' ' in cmd else [cmd]
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE)

    return p.communicate()
