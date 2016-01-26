
from charmhelpers.core.hookenv import (
    config,
    status_set,
    action_get,
    action_fail,
    log
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


cfg = config()


@hook('config-changed')
def validate_config():
    try:
        if not cfg.keys() & {'pass', 'vpe-router', 'user'}:
            raise Exception('vpe-router, user, and pass need to be set')

        out, err = router.ssh(['whoami'], cfg.get('vpe-router'),
                              cfg.get('user'), cfg.get('pass'))
        if out.strip() != cfg.get('user'):
            raise Exception('invalid credentials')
    except Exception as e:
        remove_state('vpe.configured')
        set_state('blocked', 'validation failed: %s' % e)
    finally:
        remove_state('blocked')
        set_state('vpe.configured')
        status_set('active', 'Ready!')


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

    status_set('blocked', 'VPE is not configured')


@when('vpe.configured')
@when('vpe.add-corporation')
def add_corporation():
    '''
    Create and Activate the network corporation
    '''

    domain_name = action_get('domain-name')
    iface_name = action_get('iface-name')
    vlan_id = action_get('vlan-id')
    cidr = action_get('cidr')

    iface_vlanid = '%s.%s' % (iface_name, vlan_id)

    status_set('maintenance', 'Adding corporation {}'.format(domain_name))

    # ip link add link iface_name domain_name vlan_id type vlan id vlan_id
    router.ip('link',
              'add',
              'link',
              iface_name,
              domain_name,
              vlan_id,
              'type',
              'vlan',
              'id',
              vlan_id)

    # ip link set dev iface_vlanid netns domain_name
    router.ip('link',
              'set',
              'dev',
              iface_vlanid,
              'netns',
              domain_name)

    # ip netns exec domain_name ip link set dev iface_vlanid up
    router.ip('netns',
              'exec',
              domain_name,
              'ip',
              'link',
              'set',
              'dev',
              iface_vlanid,
              'up')

    # ip netns exec domain_name ip address add cidr dev iface_vlanid
    router.ip('netns',
              'exec',
              domain_name,
              'ip',
              'address',
              'add',
              cidr,
              'dev',
              iface_vlanid)
    status_set('active', 'Ready!')


@when('vpe.configured')
@when('vpe.delete-corporation')
def delete_corporation():

    domain_name = action_get('domain-name')

    status_set('maintenance', 'Deleting corporation {}'.format(domain_name))

    # Remove all tunnels defined for this domain
    p = router.ip(
        'netns',
        'exec',
        'domain_name',
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

        router.ip(
            'netns',
            'exec',
            domain_name,
            'ip',
            'tunnel',
            'del',
            tunnel
        )

    # Remove all interfaces associated to the domain
    p = router.ip(
        'netns',
        'exec',
        'domain_name',
        'ifconfig',
        '|',
        'grep mtu',
        '|',
        'cut -d":" -f1'
    )

    ifaces = p[0].split('\n')
    for iface in ifaces:

        # ip netns exec domain_name ip link set $iface down
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

        # ip link del dev $iface
        router.ip(
            'link',
            'del',
            'dev',
            iface
        )

    # Remove the domain
    # ip netns del domain_name
    router.ip(
        'netns',
        'del',
        domain_name
    )
    status_set('active', 'Ready!')


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

    status_set('maintenance', 'Connecting domains')

    # ip tunnel add tunnel_name mode gre local local_ip remote remote_ip dev
    #    iface_name key tunnel_key csum
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
    # ip link set dev tunnel_name netns domain_name
    router.ip(
        'link',
        'set',
        'dev',
        config['tunnel-name'],
        'up'
    )

    # ip netns exec domain_name ip link set dev tunnel_name up
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

    # ip netns exec domain_name ip address add internal_local_ip peer \
    # internal_remote_ip dev tunnel_name
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
    status_set('active', 'Ready!')


@when('vpe.configured')
@when('vpe.delete-domain-connection')
def delete_domain_connection():
    ''' Remove the tunnel to another router where the domain is present '''
    domain = action_get('domain-name')
    tunnel_name = action_get('tunnel-name')

    status_set('maintenance', 'Deleting domain connection: {}'.format(domain))

    # ip netns exec domain_name ip link set tunnel_name down
    router.ip('netns',
              'exec',
              domain,
              'ip',
              'link',
              'set',
              tunnel_name,
              'down')

    # ip netns exec domain_name ip tunnel del tunnel_name
    router.ip('netns',
              'exec',
              domain,
              'ip',
              'tunnel',
              'del',
              tunnel_name)
    status_set('active', 'Ready!')
