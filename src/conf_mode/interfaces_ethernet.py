#!/usr/bin/env python3
#
# Copyright (C) 2019-2024 VyOS maintainers and contributors
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
from sys import exit
from vyos.base import Warning
from vyos.config import Config
from vyos.configdict import get_interface_dict
from vyos.configdict import is_node_changed
from vyos.configverify import verify_address
from vyos.configverify import verify_dhcpv6
from vyos.configverify import verify_interface_exists
from vyos.configverify import verify_mirror_redirect
from vyos.configverify import verify_mtu
from vyos.configverify import verify_mtu_ipv6
from vyos.configverify import verify_vlan_config
from vyos.configverify import verify_vrf
from vyos.configverify import verify_bond_bridge_member
from vyos.configverify import verify_eapol
from vyos.ethtool import Ethtool
from vyos.ifconfig import EthernetIf
from vyos.ifconfig import BondIf
from vyos.template import render_to_string
from vyos.utils.dict import dict_search
from vyos.utils.dict import dict_to_paths_values
from vyos.utils.dict import dict_set
from vyos.utils.dict import dict_delete
from vyos import ConfigError
from vyos import frr
from vyos import airbag
airbag.enable()

def update_bond_options(conf: Config, eth_conf: dict) -> list:
    """
    Return list of blocked options if interface is a bond member
    :param conf: Config object
    :type conf: Config
    :param eth_conf: Ethernet config dictionary
    :type eth_conf: dict
    :return: List of blocked options
    :rtype: list
    """
    blocked_list = []
    bond_name = list(eth_conf['is_bond_member'].keys())[0]
    config_without_defaults = conf.get_config_dict(
        ['interfaces', 'ethernet', eth_conf['ifname']],
        key_mangling=('-', '_'),
        get_first_key=True,
        no_tag_node_value_mangle=True,
        with_defaults=False,
        with_recursive_defaults=False)
    config_with_defaults = conf.get_config_dict(
        ['interfaces', 'ethernet', eth_conf['ifname']],
        key_mangling=('-', '_'),
        get_first_key=True,
        no_tag_node_value_mangle=True,
        with_defaults=True,
        with_recursive_defaults=True)
    bond_config_with_defaults = conf.get_config_dict(
        ['interfaces', 'bonding', bond_name],
        key_mangling=('-', '_'),
        get_first_key=True,
        no_tag_node_value_mangle=True,
        with_defaults=True,
        with_recursive_defaults=True)
    eth_dict_paths = dict_to_paths_values(config_without_defaults)
    eth_path_base = ['interfaces', 'ethernet', eth_conf['ifname']]

    #if option is configured under ethernet section
    for option_path, option_value in eth_dict_paths.items():
        bond_option_value = dict_search(option_path, bond_config_with_defaults)

        #If option is allowed for changing then continue
        if option_path in EthernetIf.get_bond_member_allowed_options():
            continue
        # if option is inherited from bond then set valued from bond
        if option_path in BondIf.get_inherit_bond_options():
            # If option equals to bond option then do nothing
            if option_value == bond_option_value:
                continue
            else:
                # if ethernet has option and bond interface has
                # then copy it from bond
                if bond_option_value is not None:
                    if is_node_changed(conf, eth_path_base + option_path.split('.')):
                        Warning(
                            f'Cannot apply "{option_path.replace(".", " ")}" to "{option_value}".' \
                            f' Interface "{eth_conf["ifname"]}" is a bond member.' \
                            f' Option is inherited from bond "{bond_name}"')
                    dict_set(option_path, bond_option_value, eth_conf)
                    continue
                # if ethernet has option and bond interface does not have
                # then delete it form dict and do not apply it
                else:
                    if is_node_changed(conf, eth_path_base + option_path.split('.')):
                        Warning(
                            f'Cannot apply "{option_path.replace(".", " ")}".' \
                            f' Interface "{eth_conf["ifname"]}" is a bond member.' \
                            f' Option is inherited from bond "{bond_name}"')
                    dict_delete(option_path, eth_conf)
        blocked_list.append(option_path)

    # if inherited option is not configured under ethernet section but configured under bond section
    for option_path in BondIf.get_inherit_bond_options():
        bond_option_value = dict_search(option_path, bond_config_with_defaults)
        if bond_option_value is not None:
            if option_path not in eth_dict_paths:
                if is_node_changed(conf, eth_path_base + option_path.split('.')):
                    Warning(
                        f'Cannot apply "{option_path.replace(".", " ")}" to "{dict_search(option_path, config_with_defaults)}".' \
                        f' Interface "{eth_conf["ifname"]}" is a bond member. ' \
                        f'Option is inherited from bond "{bond_name}"')
                dict_set(option_path, bond_option_value, eth_conf)
    eth_conf['bond_blocked_changes'] = blocked_list
    return None

def get_config(config=None):
    """
    Retrieve CLI config as dictionary. Dictionary can never be empty, as at least the
    interface name will be added or a deleted flag
    """
    if config:
        conf = config
    else:
        conf = Config()

    base = ['interfaces', 'ethernet']
    ifname, ethernet = get_interface_dict(conf, base, with_pki=True)

    # T5862 - default MTU is not acceptable in some environments
    # There are cloud environments available where the maximum supported
    # ethernet MTU is e.g. 1450 bytes, thus we clamp this to the adapters
    # maximum MTU value or 1500 bytes - whatever is lower
    if 'mtu' not in ethernet:
        try:
            ethernet['mtu'] = '1500'
            max_mtu = EthernetIf(ifname).get_max_mtu()
            if max_mtu < int(ethernet['mtu']):
                ethernet['mtu'] = str(max_mtu)
        except:
            pass

    if 'is_bond_member' in ethernet:
        update_bond_options(conf, ethernet)

    tmp = is_node_changed(conf, base + [ifname, 'speed'])
    if tmp: ethernet.update({'speed_duplex_changed': {}})

    tmp = is_node_changed(conf, base + [ifname, 'duplex'])
    if tmp: ethernet.update({'speed_duplex_changed': {}})

    return ethernet

def verify_speed_duplex(ethernet: dict, ethtool: Ethtool):
    """
     Verify speed and duplex
    :param ethernet: dictionary which is received from get_interface_dict
    :type ethernet: dict
    :param ethtool: Ethernet object
    :type ethtool: Ethtool
    """
    if ((ethernet['speed'] == 'auto' and ethernet['duplex'] != 'auto') or
            (ethernet['speed'] != 'auto' and ethernet['duplex'] == 'auto')):
        raise ConfigError(
            'Speed/Duplex mismatch. Must be both auto or manually configured')

    if ethernet['speed'] != 'auto' and ethernet['duplex'] != 'auto':
        # We need to verify if the requested speed and duplex setting is
        # supported by the underlying NIC.
        speed = ethernet['speed']
        duplex = ethernet['duplex']
        if not ethtool.check_speed_duplex(speed, duplex):
            raise ConfigError(
                f'Adapter does not support changing speed ' \
                f'and duplex settings to: {speed}/{duplex}!')


def verify_flow_control(ethernet: dict, ethtool: Ethtool):
    """
     Verify flow control
    :param ethernet: dictionary which is received from get_interface_dict
    :type ethernet: dict
    :param ethtool: Ethernet object
    :type ethtool: Ethtool
    """
    if 'disable_flow_control' in ethernet:
        if not ethtool.check_flow_control():
            raise ConfigError(
                'Adapter does not support changing flow-control settings!')


def verify_ring_buffer(ethernet: dict, ethtool: Ethtool):
    """
     Verify ring buffer
    :param ethernet: dictionary which is received from get_interface_dict
    :type ethernet: dict
    :param ethtool: Ethernet object
    :type ethtool: Ethtool
    """
    if 'ring_buffer' in ethernet:
        max_rx = ethtool.get_ring_buffer_max('rx')
        if not max_rx:
            raise ConfigError(
                'Driver does not support RX ring-buffer configuration!')

        max_tx = ethtool.get_ring_buffer_max('tx')
        if not max_tx:
            raise ConfigError(
                'Driver does not support TX ring-buffer configuration!')

        rx = dict_search('ring_buffer.rx', ethernet)
        if rx and int(rx) > int(max_rx):
            raise ConfigError(f'Driver only supports a maximum RX ring-buffer ' \
                              f'size of "{max_rx}" bytes!')

        tx = dict_search('ring_buffer.tx', ethernet)
        if tx and int(tx) > int(max_tx):
            raise ConfigError(f'Driver only supports a maximum TX ring-buffer ' \
                              f'size of "{max_tx}" bytes!')


def verify_offload(ethernet: dict, ethtool: Ethtool):
    """
     Verify offloading capabilities
    :param ethernet: dictionary which is received from get_interface_dict
    :type ethernet: dict
    :param ethtool: Ethernet object
    :type ethtool: Ethtool
    """
    if dict_search('offload.rps', ethernet) != None:
        if not os.path.exists(f'/sys/class/net/{ethernet["ifname"]}/queues/rx-0/rps_cpus'):
            raise ConfigError('Interface does not support RPS!')
    driver = ethtool.get_driver_name()
    # T3345 - Verify if adapter has i40e driver
    if driver == 'i40e' and 'hw-acceleration' in ethernet:
        raise ConfigError(
            'Hardware acceleration is not supported on interfaces ' \
            'with the i40e driver!')


def update_vlan(ethernet: dict, config: Config):
    """
     Update VLAN tagging
    :param ethernet: dictionary which is received from get_interface_dict
    :type ethernet: dict
    :param config: Config object
    :type config: Config
    """
    if 'vlan' in ethernet:
        if 'vlan_tag' in ethernet:
            raise ConfigError(
                'VLAN tagging cannot be set at the same time with vlan_tag!')

        if 'vlan' in ethernet:
            # T3405: check that VLAN tag exists
            verify_vlan_config(config, ethernet['ifname'], ethernet['vlan'])

            if 'ipv6' in ethernet:
                for subint in ethernet['ipv6']:
                    verify_address(subint)

            if 'ipv4' in ethernet:
                for subint in ethernet['ipv4']:
                    verify_address(subint)


def update_vlan_ip_address(ethernet: dict, config: Config):
    """
     Update VLAN IP address
    :param ethernet: dictionary which is received from get_interface_dict
    :type ethernet: dict
    :param config: Config object
    :type config: Config
    """
    if 'vlan' in ethernet:
        if ethernet.get('ipv4'):
            verify_address(ethernet['ipv4'])
        if ethernet.get('ipv6'):
            verify_address(ethernet['ipv6'])
        verify_vlan_config(config, ethernet['ifname'], ethernet['vlan'])


def configure_ethernet(config=None):
    """
     Main function to configure the Ethernet interface
    :param config: Config object
    :type config: Config
    """
    ethernet = get_config(config)
    ethtool = Ethtool(ethernet['ifname'])

    verify_speed_duplex(ethernet, ethtool)
    verify_flow_control(ethernet, ethtool)
    verify_ring_buffer(ethernet, ethtool)
    verify_offload(ethernet, ethtool)
    update_vlan(ethernet, config)
    update_vlan_ip_address(ethernet, config)

    return ethernet


def main():
    try:
        # Assuming the main configuration is needed
        configure_ethernet(Config())
    except Exception as e:
        print(f"Error during Ethernet configuration: {str(e)}")
        exit(1)

if __name__ == '__main__':
    main()

