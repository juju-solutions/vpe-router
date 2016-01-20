
from charmhelpers.core.hookenv import (
    config,
    status_set,
    action_get,
)

from charms.reactive import (
    hook,
    set_state,
    is_state,
    remove_state,
    main,
)

from charms import router


cfg = config()


@hook('install')
def deps():
    apt_install('some-stuff')


@hook('config-changed')
def configure():
    pass


@when('vpe.add-site')
def add_site():
    site = action_get('name')
    cidr = action_get('cidr')
    vlan = action_get('vland-tag')
    ethN = action_get('interface')

    link_name = '%s.%s' % (ethN, vlan)

    # move these into router which will ultimately just call ip?
    # need to figure out explicit vs abstracted
    # router.new_site(site, ethN, vlan, cidr)
    #  router.create_namespace(site)
    router.ip('netns', 'add', site)
    #  router.create_vlan(ethN, vlan)
    router.ip('link', 'add', 'link', ethN, 'name', link_name, 'type', 'vlan',
              'id', vlan)
    #  router.vlan_ns(ethN, vlan, site)
    router.ip('link', 'set', 'dev', link_name, 'netns', site)
    #  router.link_up_ns(site, link_name, cidr)
    router.ip('netns', 'exec', site, 'ip', 'link', 'set', 'dev', link_name, 'up')
    router.ip('netns', 'exec', site, 'ip', 'address', 'add', cidr, 'dev', link_name)


@when('vpe.add-route')
def add_route():
    site = action_get('site')
    name = action_get('name')
    local_addr = action_get('address.local')
    remote_addr = action_get('address.remote')

    gre_name = '%s%s' % (site, name)

    router.ip('tunnel', 'add', gre_name, 'mode', 'gre', 'local', local_addr,
              'remote', remote_addr, 'dev', iface, 'key', 1, 'csum')
    router.ip('link', 'set', 'dev', gre_name, 'netns', site)
