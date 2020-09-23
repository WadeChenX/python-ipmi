#!/usr/bin/env python
# -*- coding: utf-8 -*-

import copy

from nose.tools import eq_, raises, ok_
from mock import MagicMock

from pyipmi.base import Base
from pyipmi import interfaces, create_connection

import pyipmi.msgs.sol

from pyipmi.errors import DecodingError, EncodingError, NotSupportedError
from pyipmi.msgs import encode_message
from pyipmi.msgs import decode_message

def test_SolInfo():
    # default value
    test_fields_1 = {
            "set_in_progress": None,
            "enable": None,
            "privilege": None,
            "force_payload_auth": None,
            "force_payload_encrypt": None,
            "char_accumulate_interval": None,
            "char_send_threshold": None,
            "retry_count": None,
            "retry_interval": None,
            "nonvolatile_bit_rate": None,
            "volatile_bit_rate": None,
            "payload_channel": None,
            "payload_port": None,
    }
    sol_info = pyipmi.sol.SolInfo()
    for k, v in test_fields_1.items():
        actual_v = getattr(sol_info, k)
        eq_(v, actual_v)

    # set_in_progress
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x00')
    sol_info.refresh_info(rsp)
    eq_(sol_info.set_in_progress, "set_complete")
    decode_message(rsp, b'\x00\x11\x01')
    sol_info.refresh_info(rsp)
    eq_(sol_info.set_in_progress, "set_in_progress")
    decode_message(rsp, b'\x00\x11\x02')
    sol_info.refresh_info(rsp)
    eq_(sol_info.set_in_progress, "commit_write")

    # sol enable
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_ENABLE
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x00')
    sol_info.refresh_info(rsp)
    eq_(sol_info.enable, False)
    decode_message(rsp, b'\x00\x11\x01')
    sol_info.refresh_info(rsp)
    eq_(sol_info.enable, True)

    # sol authentication
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_AUTHENTICATION
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x02')
    sol_info.refresh_info(rsp)
    eq_(sol_info.privilege, "user")
    eq_(sol_info.force_payload_auth, False)
    eq_(sol_info.force_payload_encrypt, False)

    # sol character accumulate interval & character sending threshold
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x0c\x60')
    sol_info.refresh_info(rsp)
    eq_(sol_info.char_accumulate_interval, 0x0c)
    eq_(sol_info.char_send_threshold, 0x60)

    # sol retry
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_RETRY
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x07\x32')
    sol_info.refresh_info(rsp)
    eq_(sol_info.retry_count, 0x07)
    eq_(sol_info.retry_interval, 0x32)

    # sol non-volatile bit rate
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x0a')
    sol_info.refresh_info(rsp)
    eq_(sol_info.nonvolatile_bit_rate, 115200)

    # sol volatile bit rate
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_VOLATILE_BIT_RATE
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x0a')
    sol_info.refresh_info(rsp)
    eq_(sol_info.volatile_bit_rate, 115200)

    # sol payload channel
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_CHANNEL
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x01')
    sol_info.refresh_info(rsp)
    eq_(sol_info.payload_channel, 1)

    # sol payload port
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_PORT
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x6f\x02')
    sol_info.refresh_info(rsp)
    eq_(sol_info.payload_port, 623)

def test_sol_watch():
    sol_info = pyipmi.sol.SolInfo()

    sol_obj = pyipmi.sol.Sol()
    mock_get_sol_info = MagicMock()
    mock_get_sol_info.return_value = sol_info
    sol_obj.get_sol_info = mock_get_sol_info

    # volatile bit
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_VOLATILE_BIT_RATE
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x0a')
    sol_info.refresh_info(rsp)
    eq_(sol_info.volatile_bit_rate, 115200)

    eq_(sol_obj.sol_watch("volatile_bit_rate", 115200, timeout=1, channel=0x0e), Base.STATE_COMPLETE)
    eq_(sol_obj.sol_watch("volatile_bit_rate", 57600, timeout=1, channel=0x0e), Base.STATE_TIMEOUT)

@raises(AttributeError)
def test_SolInfo_invalid__set_in_progress():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.set_in_progress = "set_in_progress"

@raises(NotSupportedError)
def test_SolInfo_invalid__enable():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.enable = "12"

@raises(NotSupportedError)
def test_SolInfo_invalid__privilege():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.privilege = "test"

@raises(NotSupportedError)
def test_SolInfo_invalid__force_payload_auth():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.force_payload_auth = "12"

@raises(NotSupportedError)
def test_SolInfo_invalid__force_payload_encrypt():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.force_payload_encrypt = "12"

@raises(NotSupportedError)
def test_SolInfo_invalid__char_accumulate_interval():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.char_accumulate_interval = 256

@raises(NotSupportedError)
def test_SolInfo_invalid__char_send_threshold():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.char_send_threshold = 256

@raises(NotSupportedError)
def test_SolInfo_invalid__retry_count():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.retry_count = 8

@raises(NotSupportedError)
def test_SolInfo_invalid__retry_interval():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.retry_interval = 256

@raises(NotSupportedError)
def test_SolInfo_invalid__nonvolatile_bit_rate():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.nonvolatile_bit_rate = 1000

@raises(NotSupportedError)
def test_SolInfo_invalid__volatile_bit_rate():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.volatile_bit_rate = 1000

@raises(AttributeError)
def test_SolInfo_invalid__payload_channel():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.payload_channel = 1000

@raises(AttributeError)
def test_SolInfo_invalid__payload_port():
    sol_info = pyipmi.sol.SolInfo()
    sol_info.payload_port = 1000

def test_Sol_get_sol_info_valid():
    sol_obj = pyipmi.sol.Sol()

    # create fake response
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    sol_obj._sol_send_and_recv = mock_send_recv

    # start to test
    check_param_maps = (
            pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS, 
            pyipmi.msgs.sol.SOL_PARAMETER_ENABLE,
            pyipmi.msgs.sol.SOL_PARAMETER_AUTHENTICATION,
            pyipmi.msgs.sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD,
            pyipmi.msgs.sol.SOL_PARAMETER_RETRY,
            pyipmi.msgs.sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE,
            pyipmi.msgs.sol.SOL_PARAMETER_VOLATILE_BIT_RATE,
            pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_CHANNEL,
            pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_PORT,
    )

    sol_obj.get_sol_info(channel=1)
    args, _ = mock_send_recv.call_args
    reqs = args[0]
    eq_(len(reqs), len(check_param_maps))
    for req in reqs:
        ok_(req.parameter_selector in check_param_maps)


@raises(RuntimeError)
def test_Sol_set_sol_info_invalid_1():
    sol_obj = pyipmi.sol.Sol()
    sol_info = pyipmi.sol.SolInfo()

    # create fake response
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 1
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]

    sol_obj._sol_send_and_recv = mock_send_recv

    sol_obj.set_sol_info("test", channel=1)

def test_Sol_set_sol_info_valid():
    sol_obj = pyipmi.sol.Sol()

    # create fake response
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e
    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS
    req.set_selector = 0
    req.block_selector = 0
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    rsp.completion_code = 0

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = [rsp]
    sol_obj._sol_send_and_recv = mock_send_recv

    # create fake sol_info
    # set_in_progress: 0
    # enable: 1
    # auth.privilege : 2
    # auth.force_payload_auth: 0
    # auth.force_payload_encrypt: 0
    # char_accumulate_interval: 0x0c
    # char_send_threshold: 0x60
    # retry.count: 0x07
    # retry.interval: 0x32
    # nonvolatile_bit_rate: 0x0a
    # volatile_bit_rate: 0x0a
    # payload_channel: 0x01
    # payload_port: 623
    rsp_org_list = []
    org_sol_info = pyipmi.sol.SolInfo()
    req = pyipmi.msgs.sol.GetSOLConfigurationParametersReq()
    req.command.channel_number = 0x0e

    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x00')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_ENABLE
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x01')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_AUTHENTICATION
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x02')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x0c\x60')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_RETRY
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x07\x32')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x0a')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_VOLATILE_BIT_RATE
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x0a')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_CHANNEL
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x01')
    rsp_org_list.append(rsp)

    req.parameter_selector = pyipmi.msgs.sol.SOL_PARAMETER_PAYLOAD_PORT
    rsp = pyipmi.msgs.sol.GetSOLConfigurationParametersRsp(req_obj=req)
    decode_message(rsp, b'\x00\x11\x6f\x02')
    rsp_org_list.append(rsp)


    for rsp in rsp_org_list:
        req_obj = rsp.req_obj
        org_sol_info.refresh_info(rsp)

    mock_get_sol_info = MagicMock()
    mock_get_sol_info.return_value =org_sol_info 
    sol_obj.get_sol_info = mock_get_sol_info

    # test case 1: no setting
    test_sol_info = copy.deepcopy(org_sol_info)
    sol_obj.set_sol_info(test_sol_info, channel=0x0e)
    eq_(mock_send_recv.call_args, None)

    # test case 2: disable sol
    test_sol_info = copy.deepcopy(org_sol_info)
    test_sol_info.enable = False
    sol_obj.set_sol_info(test_sol_info, channel=0x0e)
    args = mock_send_recv.call_args.args
    reqs = args[0]
    param_req_map = { req.parameter_selector: req  for req in reqs }
    ok_(pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS in param_req_map.keys())
    ok_(pyipmi.msgs.sol.SOL_PARAMETER_ENABLE in param_req_map.keys())
    test_req = param_req_map[pyipmi.msgs.sol.SOL_PARAMETER_ENABLE]
    eq_(test_req.sol_enable.enable, False)

    # test case 3: enable sol, privilege = operator, force_payload_auth = True, force_payload_encrypt = True
    test_sol_info = copy.deepcopy(org_sol_info)
    test_sol_info.privilege = "operator"
    test_sol_info.force_payload_auth = True
    test_sol_info.force_payload_encrypt = True
    sol_obj.set_sol_info(test_sol_info, channel=0x0e)
    args = mock_send_recv.call_args.args
    reqs = args[0]
    param_req_map = { req.parameter_selector: req  for req in reqs }
    eq_(len(reqs), 3)
    ok_(pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS in param_req_map.keys())
    ok_(pyipmi.msgs.sol.SOL_PARAMETER_AUTHENTICATION in param_req_map.keys())
    test_req = param_req_map[pyipmi.msgs.sol.SOL_PARAMETER_AUTHENTICATION]
    eq_(test_req.sol_auth.privilege, pyipmi.sol.SolInfo.FIELD_PRIVILEDGE_LEVEL_INV["operator"])
    eq_(test_req.sol_auth.force_payload_auth, 1)
    eq_(test_req.sol_auth.force_payload_encrypt, 1)

    # test case 4: 
    # char_accumulate_interval: 0x01
    # char_send_threshold: 0x02
    # retry_count: 0x04
    # retry_interval: 0x07
    # nonvolatile_bit_rate: 9600
    # volatile_bit_rate: 57600
    test_sol_info = copy.deepcopy(org_sol_info)
    test_sol_info.char_accumulate_interval = 1
    test_sol_info.char_send_threshold = 2
    test_sol_info.retry_count = 4
    test_sol_info.retry_interval = 7
    test_sol_info.nonvolatile_bit_rate = 9600
    test_sol_info.volatile_bit_rate = 57600
    sol_obj.set_sol_info(test_sol_info, channel=0x0e)
    args = mock_send_recv.call_args.args
    reqs = args[0]
    param_req_map = { req.parameter_selector: req  for req in reqs }
    eq_(len(reqs), 6)
    ok_(pyipmi.msgs.sol.SOL_PARAMETER_SET_IN_PROGRESS in param_req_map.keys())
    ok_(pyipmi.msgs.sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD in param_req_map.keys())
    ok_(pyipmi.msgs.sol.SOL_PARAMETER_RETRY in param_req_map.keys())
    ok_(pyipmi.msgs.sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE in param_req_map.keys())
    ok_(pyipmi.msgs.sol.SOL_PARAMETER_VOLATILE_BIT_RATE in param_req_map.keys())
    test_req = param_req_map[pyipmi.msgs.sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD]
    eq_(test_req.sol_char.accumulate_interval, 1)
    eq_(test_req.sol_char.send_threshold, 2)
    test_req = param_req_map[pyipmi.msgs.sol.SOL_PARAMETER_RETRY]
    eq_(test_req.retry.count, 4)
    eq_(test_req.retry.interval, 7)
    test_req = param_req_map[pyipmi.msgs.sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE]
    eq_(test_req.nonvolatile_bit_rate.bit_rate, pyipmi.sol.SolInfo.FIELD_BIT_RATE_INV[9600])
    test_req = param_req_map[pyipmi.msgs.sol.SOL_PARAMETER_VOLATILE_BIT_RATE]
    eq_(test_req.volatile_bit_rate.bit_rate, pyipmi.sol.SolInfo.FIELD_BIT_RATE_INV[57600])



