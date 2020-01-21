#!/usr/bin/env python

from array import array

from nose.tools import eq_, raises, ok_

import pyipmi.msgs.lan

from pyipmi.errors import DecodingError, EncodingError
from pyipmi.msgs import encode_message
from pyipmi.msgs import decode_message

def test_set_lan_config_req_valid():
    m = pyipmi.msgs.lan.SetLanConfigurationParametersReq()
    m.command.channel_number = 1
    m.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS
    m.ipv4_address = 3232235881
    data = encode_message(m)
    eq_(data, b'\x01\x03\xc0\xa8\x01\x69')

    m = pyipmi.msgs.lan.SetLanConfigurationParametersReq()
    m.command.channel_number = 1
    m.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS_SOURCE
    m.ipv4_address_source.src = 2
    data = encode_message(m)
    eq_(data, b'\x01\x04\x02')

    m = pyipmi.msgs.lan.SetLanConfigurationParametersReq()
    m.command.channel_number = 1
    m.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SUBNET_MASK
    m.ipv4_subnet_mask = 4294967040
    data = encode_message(m)
    eq_(data, b'\x01\x06\xff\xff\xff\x00')

    m = pyipmi.msgs.lan.SetLanConfigurationParametersReq()
    m.command.channel_number = 1
    m.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS
    m.ipv4_default_gateway_address = 3232235777
    data = encode_message(m)
    eq_(data, b'\x01\x0c\xc0\xa8\x01\x01')

    m = pyipmi.msgs.lan.SetLanConfigurationParametersReq()
    m.command.channel_number = 1
    m.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES
    m.ipv6_ipv4_addressing_enables = 0x02
    data = encode_message(m)
    eq_(data, b'\x01\x33\x02')

    m = pyipmi.msgs.lan.SetLanConfigurationParametersReq()
    m.command.channel_number = 1
    m.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES
    m.ipv6_static_selector = 0
    m.ipv6_static_address_source.src = 0
    m.ipv6_static_address_source.enable = 1
    m.ipv6_static_address = 42540488241206025506885414467810754561
    m.ipv6_static_prefix_length = 64
    m.ipv6_static_address_status = 0
    data = encode_message(m)
    eq_(data, b'\x01\x38\x00\x80\x20\x01\x00\x01\x00\x01\xab\xcd\x00\x00\x00\x00\x00\x22\x00\x01\x40\x00')

    m = pyipmi.msgs.lan.SetLanConfigurationParametersReq()
    m.command.channel_number = 1
    m.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS
    m.ipv6_dynamic_selector = 0
    m.ipv6_dynamic_address_source.src = 1
    m.ipv6_dynamic_address = 336294682933583715844870608019971387657
    m.ipv6_dynamic_prefix_length = 64
    m.ipv6_dynamic_address_status = 0
    data = encode_message(m)
    eq_(data, b'\x01\x3b\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x02\xe0\xe8\xff\xfe\x90\x31\x09\x40\x00')

@raises(EncodingError)
def test_set_lan_config_req_invalid_no_fill():
    m = pyipmi.msgs.lan.SetLanConfigurationParametersReq()
    m.command.channel_number = 1
    m.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS
    #m.ipv4_address = 3232235881
    data = encode_message(m)


def test_get_lan_config_rsp_valid():
    # set_in_progress
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x01')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.set_in_progress.status, 1)
    decode_message(rsp, b'\x00\x11\x02')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.set_in_progress.status, 2)

    #IPv4 Address
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\xc0\xa8\x01\x69')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.ipv4_address, 3232235881)

    #IPv4 Address Source
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IP_ADDRESS_SOURCE
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x01')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.ipv4_address_source.src, 0x01)

    #IPv4 subnet_mask
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_SUBNET_MASK
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\xff\xff\xff\x00')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.ipv4_subnet_mask, 4294967040) #255.255.255.0

    #default gateway address
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\xc0\xa8\x01\x01')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.ipv4_default_gateway_address, 3232235777)

    # ipv6/ipv4  adressing enable
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x02')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.ipv6_ipv4_addressing_enables, 0x02)

    # ipv6 static address
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x00\x80\x20\x01\x00\x01\x00\x01\xab\xcd\x00\x00\x00\x00\x00\x22\x00\x01\x40\x00')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.ipv6_static_selector, 0)
    eq_(rsp.ipv6_static_address_source.src, 0)
    eq_(rsp.ipv6_static_address_source.enable, 1)
    eq_(rsp.ipv6_static_address, 42540488241206025506885414467810754561) #ipv6 = "2001:1:1:abcd::22:1"
    eq_(rsp.ipv6_static_prefix_length, 64)
    eq_(rsp.ipv6_static_address_status, 0)

    # ipv6 dynamic address
    req = pyipmi.msgs.lan.GetLanConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.lan.LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.lan.GetLanConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x00\x01\xfd\x00\x00\x00\x00\x00\x00\x00\x02\xe0\xe8\xff\xfe\x90\x31\x09\x40\x00')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.ipv6_dynamic_selector, 0)
    eq_(rsp.ipv6_dynamic_address_source.src, 1)
    eq_(rsp.ipv6_dynamic_address, 336294682933583715844870608019971387657) #ipv6 = "fd00::2e0:e8ff:fe90:3109"
    eq_(rsp.ipv6_dynamic_prefix_length, 64)
    eq_(rsp.ipv6_dynamic_address_status, 0)


