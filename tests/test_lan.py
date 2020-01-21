#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ipaddress

from nose.tools import eq_, raises, ok_
from mock import MagicMock

from pyipmi import interfaces, create_connection

import pyipmi.msgs.lan

from pyipmi.errors import DecodingError, EncodingError, NotSupportedError
from pyipmi.msgs import encode_message
from pyipmi.msgs import decode_message

def test_LanInfo():
    test_fields_1 = {
            "set_in_progress": None,
            "ipv4_address": None,
            "ipv4_address_source": None,
            "ipv4_subnet_mask": None,
            "ipv4_default_gateway_address": None,
            "ipv6_ipv4_addressing_enables": None,
            "ipv6_static_selector": None,
            "ipv6_static_address_source": None,
            "ipv6_static_address": None,
            "ipv6_static_prefix_length": None,
            "ipv6_static_address_status": None,
            "ipv6_dynamic_selector": None,
            "ipv6_dynamic_address_source": None,
            "ipv6_dynamic_address": None,
            "ipv6_dynamic_prefix_length": None,
            "ipv6_dynamic_address_status": None,
            "ipv6_cur_selector": None,
            "ipv6_cur_address_source": None,
            "ipv6_cur_address": None,
            "ipv6_cur_prefix_length": None,
            "ipv6_cur_address_status": None,
    }
    lan_info = pyipmi.lan.LanInfo()
    for k, v in test_fields_1.items():
        actual_v = getattr(lan_info, k)
        eq_(v, actual_v)

    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x01')
    lan_info.refresh_info(rsp)
    eq_(lan_info.set_in_progress, "set_in_progress")
    decode_message(rsp, b'\x00\x11\x02')
    lan_info.refresh_info(rsp)
    eq_(lan_info.set_in_progress, "commit_write")

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\xc0\xa8\x01\x69')
    lan_info.refresh_info(rsp)
    eq_(lan_info.ipv4_address, ipaddress.IPv4Address(3232235881))

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS_SOURCE
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x01')
    lan_info.refresh_info(rsp)
    eq_(lan_info.ipv4_address_source, "static_addr_by_manual")

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SUBNET_MASK
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\xff\xff\xff\x00')
    lan_info.refresh_info(rsp)
    eq_(lan_info.ipv4_subnet_mask, ipaddress.IPv4Address(4294967040))

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\xc0\xa8\x01\x01')
    lan_info.refresh_info(rsp)
    eq_(lan_info.ipv4_default_gateway_address, ipaddress.IPv4Address(3232235777))

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x02')
    lan_info.refresh_info(rsp)
    eq_(lan_info.ipv6_ipv4_addressing_enables, "ipv6_ipv4_addr_enabled")

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x00\x80\x20\x01\x00\x01\x00\x01\xab\xcd\x00\x00\x00\x00\x00\x22\x00\x01\x40\x00')
    lan_info.refresh_info(rsp)
    eq_(lan_info.ipv6_static_selector, 0)
    eq_(lan_info.ipv6_static_address_source, "ipv6_static_addr")
    eq_(lan_info.ipv6_static_address, ipaddress.IPv6Address(42540488241206025506885414467810754561))
    eq_(lan_info.ipv6_static_prefix_length, 64)
    eq_(lan_info.ipv6_static_address_status , "active")

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x02\xe0\xe8\xff\xfe\x90\x31\x09\x40\x00')
    lan_info.refresh_info(rsp)
    eq_(lan_info.ipv6_dynamic_selector, 0)
    eq_(lan_info.ipv6_dynamic_address_source, "SLAAC")
    eq_(lan_info.ipv6_dynamic_address, ipaddress.IPv6Address(336294682933583715844870608019971387657))
    eq_(lan_info.ipv6_dynamic_prefix_length, 64)
    eq_(lan_info.ipv6_dynamic_address_status , "active")

    # test combine
    lan_info._refresh_ipv6_info()
    eq_(lan_info.ipv6_cur_selector, 0)
    eq_(lan_info.ipv6_cur_address_source, "ipv6_static_addr")
    eq_(lan_info.ipv6_cur_address, ipaddress.IPv6Address(42540488241206025506885414467810754561))
    eq_(lan_info.ipv6_cur_prefix_length, 64)
    eq_(lan_info.ipv6_cur_address_status , "active")

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x00\x00\x20\x01\x00\x01\x00\x01\xab\xcd\x00\x00\x00\x00\x00\x22\x00\x01\x40\x00')
    lan_info.refresh_info(rsp)
    lan_info._refresh_ipv6_info()
    eq_(lan_info.ipv6_cur_selector, 0)
    eq_(lan_info.ipv6_cur_address_source, "SLAAC")
    eq_(lan_info.ipv6_cur_address, ipaddress.IPv6Address(336294682933583715844870608019971387657))
    eq_(lan_info.ipv6_cur_prefix_length, 64)
    eq_(lan_info.ipv6_cur_address_status , "active")
    


def test_Lan_get_lan_info_valid():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    # start to test
    check_param_maps = {
            "ipv4": {
                        pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES, 
                        pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS,
                        pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS_SOURCE,
                        pyipmi.msgs.lan.LAN_PARAMETER_SUBNET_MASK,
                        pyipmi.msgs.lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS,
                    },
            "ipv6": {
                        pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES,
                        pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES,
                        pyipmi.msgs.lan.LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS,
                    },
        }
    all_set = set()
    for k, v in check_param_maps.items():
        all_set = all_set | v

    check_param_maps["all"] = all_set

    lan_obj.get_lan_info(channel=1, info_type="ipv4")
    args, _ = mock_send_recv.call_args
    reqs = args[0]
    eq_(len(reqs), len(check_param_maps["ipv4"]))
    for req in reqs:
        ok_(req.parameter_selector in check_param_maps["ipv4"])

    lan_obj.get_lan_info(channel=1, info_type="ipv6")
    args, _ = mock_send_recv.call_args
    reqs = args[0]
    eq_(len(reqs), len(check_param_maps["ipv6"]))
    for req in reqs:
        ok_(req.parameter_selector in check_param_maps["ipv6"])

    lan_obj.get_lan_info(channel=1, info_type="all")
    args, _ = mock_send_recv.call_args
    reqs = args[0]
    eq_(len(reqs), len(check_param_maps["all"]))
    for req in reqs:
        ok_(req.parameter_selector in check_param_maps["all"])


@raises(NotSupportedError)
def test_Lan_get_lan_info_invalid():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.get_lan_info(channel=1, info_type="test")


@raises(RuntimeError)
def test_Lan_set_lan_info_ipv4_invalid_1():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(channel=1, ipv4_enable=True)

@raises(RuntimeError)
def test_Lan_set_lan_info_ipv4_invalid_2():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(
            channel=1, 
            ipv4_enable=True, 
            addr_src='dfdfd',
            addr=ipaddress.IPv4Address("192.168.1.105"),
            subnet_mask=ipaddress.IPv4Address("255.255.255.0"),
            gateway=ipaddress.IPv4Address("192.168.1.1")
    )

@raises(RuntimeError)
def test_Lan_set_lan_info_ipv4_invalid_3():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(
            channel=1, 
            ipv4_enable=True, 
            addr_src='static_addr_by_manual',
            addr='dfdf',
            subnet_mask=ipaddress.IPv4Address("255.255.255.0"),
            gateway=ipaddress.IPv4Address("192.168.1.1")
    )

@raises(RuntimeError)
def test_Lan_set_lan_info_ipv4_invalid_4():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(
            channel=1, 
            ipv4_enable=True, 
            addr_src='static_addr_by_manual',
            addr=ipaddress.IPv4Address("192.168.1.105"),
            subnet_mask='dfdf',
            gateway=ipaddress.IPv4Address("192.168.1.1")
    )

@raises(RuntimeError)
def test_Lan_set_lan_info_ipv4_invalid_5():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(
            channel=1, 
            ipv4_enable=True, 
            addr_src='static_addr_by_manual',
            addr=ipaddress.IPv4Address("192.168.1.105"),
            subnet_mask=ipaddress.IPv4Address("255.255.255.0"),
            gateway="dfdf"
    )

def test_Lan_set_lan_info_ipv4_valid():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]
    lan_obj._lan_send_and_recv = mock_send_recv

    # create fake lan_info
    # IPv6/IPv4 all enable
    # IPv4 source : dhcp
    # IPv4 address: 192.168.1.105
    # IPv4 subnet mask: 255.255.255.0
    # IPv4 default gateway: 192.168.1.1
    rsp_org_list = []
    test_lan_info = pyipmi.lan.LanInfo()
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x02')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\xc0\xa8\x01\x69')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS_SOURCE
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x02')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SUBNET_MASK
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\xff\xff\xff\x00')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\xc0\xa8\x01\x01')
    rsp_org_list.append(rsp)

    for rsp in rsp_org_list:
        req_obj = rsp.req_obj
        test_lan_info.refresh_info(rsp)

    mock_get_lan_info = MagicMock()
    mock_get_lan_info.return_value = test_lan_info
    lan_obj.get_lan_info = mock_get_lan_info

    # test case 1: disable ipv4
    lan_obj.set_lan_info(channel=1, ipv4_enable=False)
    args = mock_send_recv.call_args.args
    reqs = args[0]
    param_req_map = { req.parameter_selector: req  for req in reqs }
    ok_(pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES in param_req_map.keys())
    test_req = param_req_map[pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES]
    eq_(test_req.ipv6_ipv4_addressing_enables, pyipmi.lan.LanInfo.FIELD_IPV6_IPV4_ADDRESSING_ENABLES_INV["ipv6_addr_enable_only"])

    # test case 2: enable ipv4, addr_src is dhcp
    lan_obj.set_lan_info(channel=1, ipv4_enable=True, addr_src='dhcp')
    args = mock_send_recv.call_args.args
    reqs = args[0]
    param_req_map = { req.parameter_selector: req  for req in reqs }
    eq_(len(reqs), 1)
    ok_(pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS_SOURCE in param_req_map.keys())
    test_req = param_req_map[pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS_SOURCE]
    eq_(test_req.ipv4_address_source, pyipmi.lan.LanInfo.FIELD_IP_ADDRESS_SOURCE_INV["dhcp"])

    # test case 3: enable ipv4, settings ip_addr: 192.168.1.104, but others remain the same.
    lan_obj.set_lan_info(channel=1, ipv4_enable=True, addr=ipaddress.IPv4Address("192.168.1.104"))
    args = mock_send_recv.call_args.args
    reqs = args[0]
    param_req_map = { req.parameter_selector: req  for req in reqs }
    eq_(len(reqs), 4)
    ok_(pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS_SOURCE in param_req_map.keys())
    ok_(pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS in param_req_map.keys())
    ok_(pyipmi.msgs.lan.LAN_PARAMETER_SUBNET_MASK in param_req_map.keys())
    ok_(pyipmi.msgs.lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS in param_req_map.keys())

    test_req = param_req_map[pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS_SOURCE]
    eq_(test_req.ipv4_address_source, pyipmi.lan.LanInfo.FIELD_IP_ADDRESS_SOURCE_INV["static_addr_by_manual"])
    test_req = param_req_map[pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS]
    eq_(test_req.ipv4_address, int(ipaddress.IPv4Address("192.168.1.104")))
    test_req = param_req_map[pyipmi.msgs.lan.LAN_PARAMETER_SUBNET_MASK]
    eq_(test_req.ipv4_subnet_mask, int(ipaddress.IPv4Address("255.255.255.0")))
    test_req = param_req_map[pyipmi.msgs.lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS]
    eq_(test_req.ipv4_default_gateway_address, int(ipaddress.IPv4Address("192.168.1.1")))


def test_Lan_set_lan_info_ipv6_valid():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]
    lan_obj._lan_send_and_recv = mock_send_recv

    # create fake lan_info
    # IPv6/IPv4 all enable
    # IPv6 source : DHCPv6
    # IPv6 static addr: 0x00 .. 
    # IPv6 dynamic addr: fd00::2e0:e8ff:fe90:3109
    # IPv6 prefix: 64
    # IPv6 selector: 0
    rsp_org_list = []
    test_lan_info = pyipmi.lan.LanInfo()
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x02')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x01\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x02\xe0\xe8\xff\xfe\x90\x31\x09\x40\x00')
    rsp_org_list.append(rsp)

    for rsp in rsp_org_list:
        req_obj = rsp.req_obj
        test_lan_info.refresh_info(rsp)

    mock_get_lan_info = MagicMock()
    mock_get_lan_info.return_value = test_lan_info
    lan_obj.get_lan_info = mock_get_lan_info


    # test case 1: disable ipv6
    lan_obj.set_lan_info(channel=1, ipv6_enable=False)
    args = mock_send_recv.call_args.args
    reqs = args[0]
    param_req_map = { req.parameter_selector: req  for req in reqs }
    ok_(pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES in param_req_map.keys())
    test_req = param_req_map[pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES]
    eq_(test_req.ipv6_ipv4_addressing_enables, pyipmi.lan.LanInfo.FIELD_IPV6_IPV4_ADDRESSING_ENABLES_INV["ipv6_addr_disabled"])

    # test case 2: enable ipv6, addr_src is dhcpv6
    lan_obj.set_lan_info(channel=1, ipv6_enable=True, v6_addr_src='DHCPv6')
    args = mock_send_recv.call_args.args
    reqs = args[0]
    param_req_map = { req.parameter_selector: req  for req in reqs }
    eq_(len(reqs), 1)
    ok_(pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES in param_req_map.keys())
    test_req = param_req_map[pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES]
    eq_(test_req.ipv6_static_address_source.src, 0)
    eq_(test_req.ipv6_static_address_source.enable, 0)
    eq_(test_req.ipv6_static_address, 0)
    eq_(test_req.ipv6_static_prefix_length, 0)
    eq_(test_req.ipv6_static_address_status, 0)

    # test case 3: enable ipv6, settings ip_addr: fd00::2e0:e8ff:fe90:3109, but others remain the same.
    lan_obj.set_lan_info(
            channel=1, 
            ipv6_enable=True, 
            v6_addr_src="ipv6_static_addr", 
            v6_selector=0, 
            v6_addr=ipaddress.IPv6Address("fd00::2e0:e8ff:fe90:3109"),
            v6_prefix_length=64
    )
    args = mock_send_recv.call_args.args
    reqs = args[0]
    param_req_map = { req.parameter_selector: req  for req in reqs }
    eq_(len(reqs), 1)
    ok_(pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES in param_req_map.keys())
    test_req = param_req_map[pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES]
    eq_(test_req.ipv6_static_address_source.src, pyipmi.lan.LanInfo.FIELD_IPV6_ADDRESS_SOURCE_INV["ipv6_static_addr"])
    eq_(test_req.ipv6_static_address_source.enable, 1)
    eq_(test_req.ipv6_static_address, int(ipaddress.IPv6Address("fd00::2e0:e8ff:fe90:3109")))
    eq_(test_req.ipv6_static_prefix_length, 64)



@raises(RuntimeError)
def test_Lan_set_lan_info_ipv6_invalid_1():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(
            channel=1, 
            ipv6_enable=True
    )

@raises(RuntimeError)
def test_Lan_set_lan_info_ipv6_invalid_2():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    #lan_obj.set_lan_info(
    #        channel=1, 
    #        ipv6_enable=True,
    #        v6_addr_src="ipv6_static_addr",
    #        v6_selector=0,
    #        v6_addr=ipaddress.IPv6Address("fd00::2e0:e8ff:fe90:3109"),
    #        v6_prefix_length=64
    #)
    lan_obj.set_lan_info(
            channel=1, 
            ipv6_enable=True,
            v6_addr_src="dfdffdf",
            v6_selector=0,
            v6_addr=ipaddress.IPv6Address("fd00::2e0:e8ff:fe90:3109"),
            v6_prefix_length=64
    )

@raises(RuntimeError)
def test_Lan_set_lan_info_ipv6_invalid_3():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(
            channel=1, 
            ipv6_enable=True,
            v6_addr_src="ipv6_static_addr",
            v6_selector='erer',
            v6_addr=ipaddress.IPv6Address("fd00::2e0:e8ff:fe90:3109"),
            v6_prefix_length=64
    )

@raises(RuntimeError)
def test_Lan_set_lan_info_ipv6_invalid_4():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(
            channel=1, 
            ipv6_enable=True,
            v6_addr_src="ipv6_static_addr",
            v6_selector=0,
            v6_addr='dere',
            v6_prefix_length=64
    )

@raises(RuntimeError)
def test_Lan_set_lan_info_ipv6_invalid_5():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(
            channel=1, 
            ipv6_enable=True,
            v6_addr_src="ipv6_static_addr",
            v6_selector=0,
            v6_addr=ipaddress.IPv6Address("fd00::2e0:e8ff:fe90:3109"),
            v6_prefix_length='ererer'
    )

@raises(RuntimeError)
def test_Lan_set_lan_info_invalid_1():
    lan_obj = pyipmi.lan.Lan()

    # create fake response
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    lan_obj._lan_send_and_recv = mock_send_recv

    lan_obj.set_lan_info(
            channel=1, 
            ipv4_enable=False,
            ipv6_enable=False
    )
