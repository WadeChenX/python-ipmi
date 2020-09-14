#!/usr/bin/env python

from array import array

from nose.tools import eq_, raises, ok_

import pyipmi.msgs.sol

from pyipmi.errors import DecodingError, EncodingError
from pyipmi.msgs import encode_message
from pyipmi.msgs import decode_message

def test_set_sol_config_req_valid():
    # set_in_progress
    m = pyipmi.msgs.sol.SetSOLConfigurationParametersReq()
    m.command.channel_number = 0x0e
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS
    m.set_in_progress.status = 0x01
    data = encode_message(m)
    eq_(data, b'\x0e\x00\x01')

    # sol enable
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_ENABLE
    m.sol_enable.enable = 1
    data = encode_message(m)
    eq_(data, b'\x0e\x01\x01')

    # sol authentication
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_AUTHENTICATION
    m.sol_auth.privilege = 3
    m.sol_auth.force_payload_auth = 0
    m.sol_auth.force_payload_encrypt = 0
    data = encode_message(m)
    eq_(data, b'\x0e\x02\x03')

    # sol character accumulate interval & character sending threshold
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD
    m.sol_char.accumulate_interval = 0x0c
    m.sol_char.send_threshold = 0x60
    data = encode_message(m)
    eq_(data, b'\x0e\x03\x0c\x60')

    # sol retry
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_RETRY
    m.retry.count = 0x07
    m.retry.interval = 0x32
    data = encode_message(m)
    eq_(data, b'\x0e\x04\x07\x32')

    # sol non-volatile bit rate
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE
    m.nonvolatile_bit_rate.bit_rate = 0x0a
    data = encode_message(m)
    eq_(data, b'\x0e\x05\x0a')

    # sol volatile bit rate
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_VOLATILE_BIT_RATE
    m.volatile_bit_rate.bit_rate = 0x0a
    data = encode_message(m)
    eq_(data, b'\x0e\x06\x0a')

    # sol payload channel
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_CHANNEL
    m.payload_channel = 1
    data = encode_message(m)
    eq_(data, b'\x0e\x07\x01')

    # sol payload port
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_PORT
    m.payload_port = 623
    data = encode_message(m)
    eq_(data, b'\x0e\x08\x6f\x02')

@raises(EncodingError)
def test_set_lan_config_req_invalid_no_fill():
    m = pyipmi.msgs.lan.SetLanConfigurationParametersReq()
    m.command.channel_number = 0x0e
    m.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD
    data = encode_message(m)


def test_get_sol_config_rsp_valid():
    # set_in_progress
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x00')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.set_in_progress.status, 0)
    decode_message(rsp, b'\x00\x11\x01')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.set_in_progress.status, 1)
    decode_message(rsp, b'\x00\x11\x02')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.set_in_progress.status, 2)

    # sol enable
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_ENABLE
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x01')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.sol_enable.enable, 1)
    decode_message(rsp, b'\x00\x11\x00')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.sol_enable.enable, 0)

    # sol authentication
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_AUTHENTICATION
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x02')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.sol_auth.privilege, 0x02)
    eq_(rsp.sol_auth.force_payload_auth, 0)
    eq_(rsp.sol_auth.force_payload_encrypt, 0)

    # sol character accumulate interval & character sending threshold
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x0c\x60')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.sol_char.accumulate_interval, 0x0c) 
    eq_(rsp.sol_char.send_threshold, 0x60) 

    # sol retry
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_RETRY
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x07\x32')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.retry.count, 0x07)
    eq_(rsp.retry.interval, 0x32)

    # sol non-volatile bit rate
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x0a')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.nonvolatile_bit_rate.bit_rate, 0x0a)

    # sol volatile bit rate
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_VOLATILE_BIT_RATE
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x0a')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.volatile_bit_rate.bit_rate, 0x0a)

    # sol payload channel
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_CHANNEL
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x01')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.payload_channel, 0x01)

    # sol payload port
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_PORT
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    ok_(rsp.req_obj is not None)
    decode_message(rsp, b'\x00\x11\x6f\x02')
    eq_(rsp.completion_code, 0x00)
    eq_(rsp.payload_port, 0x026f)


