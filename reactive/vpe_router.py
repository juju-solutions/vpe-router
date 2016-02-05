
from charmhelpers.core.hookenv import (
    config,
    status_set,
    action_get,
    action_fail,
    log,
)

from charms.reactive import (
    hook,
    when,
    when_not,
    helpers,
    set_state,
    remove_state,
)

from charms import router
import subprocess

cfg = config()


@hook('config-changed')
def validate_config():
    try:
        """
        If the ssh credentials are available, we'll act as a proxy charm.
        Otherwise, we execute against the unit we're deployed on to.
        """
        if all(k in cfg for k in ['pass', 'vpe-router', 'user']):
            routerip = cfg['vpe-router']
            user = cfg['user']
            passwd = cfg['pass']

            if routerip and user and passwd:
                out, err = router.ssh(['whoami'], routerip,
                                      user, passwd)
                if out.strip() != user:
                    raise Exception('invalid credentials')

        set_state('vpe.configured')
        status_set('active', 'ready!')

    except Exception as e:
        log(repr(e))
        remove_state('vpe.configured')
        status_set('blocked', 'validation failed: %s' % e)


@when_not('vpe.configured')
def not_ready_add():
    actions = [
        'vpe.add-corporation',
        'vpe.connect-domains',
        'vpe.delete-domain-connections',
        'vpe.remove-corporation',
    ]

    if helpers.any_states(*actions):
        action_fail('VPE is not configured')

    status_set('blocked', 'vpe is not configured')


@when('vpe.configured')
@when('vpe.add-corporation')
def add_corporation():
    '''
    Create and Activate the network corporation
    '''
    domain_name = action_get('domain-name')
    iface_name = action_get('iface-name')
    # HACK: python's list, used deeper, throws an exception on ints in a tuple
    vlan_id = str(action_get('vlan-id'))
    cidr = action_get('cidr')

    iface_vlanid = '%s.%s' % (iface_name, vlan_id)

    status_set('maintenance', 'adding corporation {}'.format(domain_name))

    """
    Attempt to run all commands to add the network corporation. If any step
    fails, abort and call `delete_corporation()` to undo.
    """
    try:
        """
        $ ip link add link eth3 name eth3.103 type vlan id 103
        """
        router.ip('link',
                  'add',
                  'link',
                  iface_name,
                  'name',
                  iface_vlanid,
                  'type',
                  'vlan',
                  'id',
                  vlan_id)

        """
        $ ip netns add domain
        """
        router.ip('netns',
                  'add',
                  domain_name)

        """
        $ ip link set dev eth3.103 netns corpB
        """
        router.ip('link',
                  'set',
                  'dev',
                  iface_vlanid,
                  'netns',
                  domain_name)

        """
        $ ip netns exec corpB ip link set dev eth3.103 up
        """
        router.ip('netns',
                  'exec',
                  domain_name,
                  'ip',
                  'link',
                  'set',
                  'dev',
                  iface_vlanid,
                  'up')

        """
        $ ip netns exec corpB ip address add 10.0.1.1/24 dev eth3.103
        """
        router.ip('netns',
                  'exec',
                  domain_name,
                  'ip',
                  'address',
                  'add',
                  cidr,
                  'dev',
                  iface_vlanid)

    except subprocess.CalledProcessError as e:
        delete_corporation()
        action_fail('Command failed: %s (%s)' % (' '.join(e.cmd), str(e.output)))
    finally:
        remove_state('vpe.add-corporation')
        status_set('active', 'ready!')


@when('vpe.configured')
@when('vpe.delete-corporation')
def delete_corporation():

    domain_name = action_get('domain-name')

    status_set('maintenance', 'deleting corporation {}'.format(domain_name))

    try:
        """
        Remove all tunnels defined for this domain

        $ ip netns exec domain_name ip tun show
            | grep gre
            | grep -v "remote any"
            | cut -d":" -f1
        """
        p = router.ip(
            'netns',
            'exec',
            domain_name,
            'ip',
            'tun',
            'show',
            '|',
            'grep',
            'gre',
            '|',
            'grep',
            '-v',
            '"remote any"',
            '|',
            'cut -d":" -f1'
        )

        # `p` should be a tuple of (stdout, stderr)
        tunnels = p[0].split('\n')

        for tunnel in tunnels:
            try:
                """
                $ ip netns exec domain_name ip link set $tunnel_name down
                """
                router.ip(
                    'netns',
                    'exec',
                    domain_name,
                    'ip',
                    'link',
                    'set',
                    tunnel,
                    'down'
                )
            except subprocess.CalledProcessError as e:
                log('Command failed: %s (%s)' % (' '.join(e.cmd), str(e.output)))
                pass

            try:
                """
                $ ip netns exec domain_name ip tunnel del $tunnel_name
                """
                router.ip(
                    'netns',
                    'exec',
                    domain_name,
                    'ip',
                    'tunnel',
                    'del',
                    tunnel
                )
            except subprocess.CalledProcessError as e:
                log('Command failed: %s (%s)' % (' '.join(e.cmd), str(e.output)))
                pass

        """
        Remove all interfaces associated to the domain

        $ ip netns exec domain_name ifconfig | grep mtu | cut -d":" -f1
        """
        p = router.ip(
            'netns',
            'exec',
            domain_name,
            'ifconfig',
            '|',
            'grep mtu',
            '|',
            'cut -d":" -f1'
        )

        ifaces = p[0].split('\n')
        for iface in ifaces:

            try:
                """
                $ ip netns exec domain_name ip link set $iface down
                """
                router.ip(
                    'netns',
                    'exec',
                    domain_name,
                    'ip',
                    'link',
                    'set',
                    iface,
                    'down'
                )
            except subprocess.CalledProcessError as e:
                log('Command failed: %s (%s)' % (' '.join(e.cmd), str(e.output)))
                pass

            try:
                """
                $ ip link del dev $iface
                """
                router.ip(
                    'link',
                    'del',
                    'dev',
                    iface
                )
            except subprocess.CalledProcessError as e:
                log('Command failed: %s (%s)' % (' '.join(e.cmd), str(e.output)))
                pass

        try:
            """
            Remove the domain

            $ ip netns del domain_name
            """
            router.ip(
                'netns',
                'del',
                domain_name
            )
        except subprocess.CalledProcessError as e:
            log('Command failed: %s (%s)' % (' '.join(e.cmd), str(e.output)))
            pass

    except:
        # Do nothing
        log('delete-corporation failed.')
        pass

    finally:
        remove_state('vpe.delete-corporation')
        status_set('active', 'ready!')


@when('vpe.configured')
@when('vpe.connect-domains')
def connect_domains():

    params = [
        'domain-name',
        'iface-name',
        'tunnel-name',
        'local-ip',
        'remote-ip',
        'tunnel-key',
        'internal-local-ip',
        'internal-remote-ip',
        'tunnel-type'
    ]

    config = {}
    for p in params:
        config[p] = action_get(p)

    status_set('maintenance', 'connecting domains')

    try:
        """
        $ ip tunnel add tunnel_name mode gre local local_ip remote remote_ip dev
            iface_name key tunnel_key csum
        """
        router.ip(
            'tunnel',
            'add',
            config['tunnel-name'],
            'mode',
            config['tunnel-type'],
            'local',
            config['local-ip'],
            'remote',
            config['remote-ip'],
            'dev',
            config['iface-name'],
            'key',
            config['tunnel-key'],
            'csum'
        )

        """
        $ ip link set dev tunnel_name netns domain_name
        """
        router.ip(
            'link',
            'set',
            'dev',
            config['tunnel-name'],
            'netns',
            config['domain-name']
        )

        """
        $ ip netns exec domain_name ip link set dev tunnel_name up
        """
        router.ip(
            'netns',
            'exec',
            config['domain-name'],
            'ip',
            'link',
            'set',
            'dev',
            config['tunnel-name'],
            'up'
        )

        """
        $ ip netns exec domain_name ip address add internal_local_ip peer
            internal_remote_ip dev tunnel_name
        """
        router.ip(
            'netns',
            'exec',
            config['domain-name'],
            'ip',
            'address',
            'add',
            config['internal-local-ip'],
            'peer',
            config['internal-remote-ip'],
            'dev',
            config['tunnel-name']
        )
    except subprocess.CalledProcessError as e:
        delete_domain_connection()
        action_fail('Command failed: %s (%s)' % (' '.join(e.cmd), str(e.output)))
    finally:
        remove_state('vpe.connect-domains')
        status_set('active', 'ready!')


@when('vpe.configured')
@when('vpe.delete-domain-connection')
def delete_domain_connection():
    ''' Remove the tunnel to another router where the domain is present '''
    domain = action_get('domain-name')
    tunnel_name = action_get('tunnel-name')

    status_set('maintenance', 'deleting domain connection: {}'.format(domain))

    try:

        try:
            """
            $ ip netns exec domain_name ip link set tunnel_name down
            """
            router.ip('netns',
                      'exec',
                      domain,
                      'ip',
                      'link',
                      'set',
                      tunnel_name,
                      'down')
        except subprocess.CalledProcessError as e:
            pass

        try:
            """
            $ ip netns exec domain_name ip tunnel del tunnel_name
            """
            router.ip('netns',
                      'exec',
                      domain,
                      'ip',
                      'tunnel',
                      'del',
                      tunnel_name)
        except subprocess.CalledProcessError as e:
            pass

    except:
        pass
    finally:
        remove_state('vpe.delete-domain-connection')
        status_set('active', 'ready!')
