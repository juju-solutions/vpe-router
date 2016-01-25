
from charmhelpers.core.hookenv import (
    config,
    status_set,
    action_get,
    action_fail,
    log
)

from charms.reactive import (
    hook,
    when
)

from charms import router


cfg = config()


@hook('install')
def deps():
    # apt_install('some-stuff')
    pass


@hook('config-changed')
def configure():
    pass


@when('vpe.add-corporation')
def add_corporation():
    '''
    Create and Activate the network corporation
    '''

    domain_name = action_get('domain_name')
    iface_name = action_get('iface_name')
    vlan_id = action_get('vlan_id')
    cidr = action_get('cidr')

    missing = []
    for item in [domain_name, iface_name, vlan_id, cidr]:
        if not item:
            missing.append(item)

    if len(missing) > 0:
        log('CRITICAL', 'Unable to complete operation due to missing required'
            'param: {}'.format('item'))

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
        if not config[p]:
            return action_fail('Missing required value for parameter %s' % p)

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


@when('vpe.remove-site')
def remove_route():
    pass
