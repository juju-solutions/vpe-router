
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
        self.do('ip', 'link', 'set', 'dev', iface, 'up')
        self.do('ip', 'address', 'add', cidr, 'dev', iface)

    def add_iface(self, iface):
        ip('link', 'set', 'dev', iface, 'netns', self.name)

    def do(self, *cmd):
        ip(*['netns', 'exec', self.name] + cmd)


def ip(*args):
    return _run(['ip'] + list(args))


def _run(cmd, env=None):
    if isinstance(cmd, str):
        cmd = cmd.split() if ' ' in cmd else [cmd]

    p = subprocess.Popen(cmd,
                         env=env,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    retcode = p.poll()
    if retcode > 0:
        raise subprocess.CalledProcessError(returncode=retcode,
                                            cmd=cmd,
                                            output=stderr.decode("utf-8").strip())
    return (''.join(stdout), ''.join(stderr))
