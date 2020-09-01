#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nose.tools import eq_, raises, ok_
from mock import MagicMock

from pyipmi.chassis import Chassis
from pyipmi.chassis import ChassisStatus
from pyipmi.chassis import ChassisInfo
import pyipmi.msgs.chassis
from pyipmi.msgs import encode_message
from pyipmi.msgs import decode_message
from pyipmi.errors import DecodingError, EncodingError, NotSupportedError


def test_chassisstatus_object():
    msg = pyipmi.msgs.chassis.GetChassisStatusRsp()
    decode_message(msg, b'\x00\xff\xff\x5f')

    status = ChassisStatus(msg)

    eq_(status.power_on, True)
    eq_(status.overload, True)
    eq_(status.interlock, True)
    eq_(status.fault, True)
    eq_(status.control_fault, True)
    eq_(status.restore_policy, ChassisInfo.FIELD_CURRENT_POWER_RESTORE_POLICY[3])

    ok_('ac_failed' in status.last_event)
    ok_('overload' in status.last_event)
    ok_('interlock' in status.last_event)
    ok_('fault' in status.last_event)
    ok_('power_on_via_ipmi' in status.last_event)

    ok_('intrusion' in status.chassis_state)
    ok_('front_panel_lockout' in status.chassis_state)
    ok_('drive_fault' in status.chassis_state)
    ok_('cooling_fault' in status.chassis_state)

    eq_(status.id_cmd_state_info_support, True)
    eq_('interval_on', status.chassis_id_state)

def test_chassis_turn_id_req_valid():
    rsp = pyipmi.msgs.chassis.ChassisIdentifyRsp()
    decode_message(rsp, b'\x00')
    chassis_obj = Chassis()

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = rsp
    chassis_obj.send_message = mock_send_recv

    chassis_obj.chassis_turn_id(state="on")
    req = mock_send_recv.call_args.args[0]
    eq_(req.interval, 0)
    eq_(req.force_id_on.turn_on, 1)

    chassis_obj.chassis_turn_id(state="off")
    req = mock_send_recv.call_args.args[0]
    eq_(req.interval, 0)
    eq_(req.force_id_on.turn_on, 0)

    chassis_obj.chassis_turn_id(state="interval_on", value=100)
    req = mock_send_recv.call_args.args[0]
    eq_(req.interval, 100)
    eq_(req.force_id_on.turn_on, 0)



@raises(NotSupportedError)
def test_chassis_turn_id_invalid_1():
    rsp = pyipmi.msgs.chassis.ChassisIdentifyRsp()
    decode_message(rsp, b'\x00')
    chassis_obj = Chassis()

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = rsp
    chassis_obj.send_message = mock_send_recv

    chassis_obj.chassis_turn_id(state="kk")

@raises(NotSupportedError)
def test_chassis_turn_id_invalid_2():
    rsp = pyipmi.msgs.chassis.ChassisIdentifyRsp()
    decode_message(rsp, b'\x00')
    chassis_obj = Chassis()

    mock_send_recv = MagicMock()
    mock_send_recv.return_value = rsp
    chassis_obj.send_message = mock_send_recv

    chassis_obj.chassis_turn_id(state="interval_on", value = 1000)
