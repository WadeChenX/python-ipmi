# Copyright (c) 2014  Kontron Europe GmbH
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA

from __future__ import absolute_import

from .msgs import create_request_by_name
from .utils import check_completion_code
from .state import State
from .errors import NotSupportedError

from .msgs.chassis import \
        CONTROL_POWER_DOWN, CONTROL_POWER_UP, CONTROL_POWER_CYCLE, \
        CONTROL_HARD_RESET, CONTROL_DIAGNOSTIC_INTERRUPT, \
        CONTROL_SOFT_SHUTDOWN

class ChassisInfo:
    FIELD_CURRENT_POWER_RESTORE_POLICY= {
            0: "power_off",
            1: "restore",
            2: "power_on",
            3: "unknown",
    }
    FIELD_CURRENT_POWER_RESTORE_POLICY_INV = {v:k for k, v in FIELD_CURRENT_POWER_RESTORE_POLICY.items()}

    FIELD_ID_STATE = {
            0: "off",
            1: "interval_on",
            2: "on",
            3: "reserved"
    }
    FIELD_ID_STATE_INV = {v:k for k, v in FIELD_ID_STATE.items()}


class Chassis(object):
    def get_chassis_status(self):
        return ChassisStatus(self.send_message_with_name('GetChassisStatus'))

    def chassis_control(self, option):
        req = create_request_by_name('ChassisControl')
        req.control.option = option
        rsp = self.send_message(req)
        check_completion_code(rsp.completion_code)

    def chassis_control_power_down(self):
        self.chassis_control(CONTROL_POWER_DOWN)

    def chassis_control_power_up(self):
        self.chassis_control(CONTROL_POWER_UP)

    def chassis_control_power_cycle(self):
        self.chassis_control(CONTROL_POWER_CYCLE)

    def chassis_control_hard_reset(self):
        self.chassis_control(CONTROL_HARD_RESET)

    def chassis_control_diagnostic_interrupt(self):
        self.chassis_control(CONTROL_DIAGNOSTIC_INTERRUPT)

    def chassis_control_soft_shutdown(self):
        self.chassis_control(CONTROL_SOFT_SHUTDOWN)

    def chassis_turn_id(self, state, value=0):
        if state not in ChassisInfo.FIELD_ID_STATE_INV.keys():
            raise NotSupportedError("ERROR: 'state' = {}, not known.".format(state))

        if value not in range(0, 256):
            raise NotSupportedError("ERROR: 'value' = {}, not 0~255.".format(value))

        req = create_request_by_name('ChassisIdentify')
        if ChassisInfo.FIELD_ID_STATE_INV[state] == 2: 
            # turn on id
            req.force_id_on.turn_on = 1
            req.interval = 0

        elif ChassisInfo.FIELD_ID_STATE_INV[state] == 0:
            # turn off id
            req.interval = 0
            req.force_id_on.turn_on = 0

        else:
            # turn on id by interval 
            req.interval = value
            req.force_id_on.turn_on = 0

        rsp = self.send_message(req)
        check_completion_code(rsp.completion_code)

class ChassisStatus(State):
    power_on = None
    overload = None
    interlock = None
    fault = None
    control_fault = None
    restore_policy = None
    id_cmd_state_info_support=None
    chassis_id_state=None
    front_panel_button_capabilities=None
    last_event = []
    chassis_state = []


    def _from_response(self, rsp):
        self.power_on = bool(rsp.current_power_state.power_on)
        self.overload = bool(rsp.current_power_state.power_overload)
        self.interlock = bool(rsp.current_power_state.interlock)
        self.fault = bool(rsp.current_power_state.power_fault)
        self.control_fault = bool(rsp.current_power_state.power_control_fault)
        self.restore_policy = ChassisInfo.FIELD_CURRENT_POWER_RESTORE_POLICY[rsp.current_power_state.power_restore_policy]
        self.id_cmd_state_info_support = bool(rsp.misc_chassis_state.id_cmd_state_info_support)
        self.chassis_id_state = ChassisInfo.FIELD_ID_STATE[rsp.misc_chassis_state.chassis_id_state]
        if rsp.front_panel_button_capabilities is not None:
            self.front_panel_button_capabilities=rsp.front_panel_button_capabilities

        if rsp.last_power_event.ac_failed:
            self.last_event.append('ac_failed')
        if rsp.last_power_event.power_overload:
            self.last_event.append('overload')
        if rsp.last_power_event.power_interlock:
            self.last_event.append('interlock')
        if rsp.last_power_event.power_fault:
            self.last_event.append('fault')
        if rsp.last_power_event.power_is_on_via_ipmi_command:
            self.last_event.append('power_on_via_ipmi')

        if rsp.misc_chassis_state.chassis_intrusion_active:
            self.chassis_state.append('intrusion')
        if rsp.misc_chassis_state.front_panel_lockout_active:
            self.chassis_state.append('front_panel_lockout')
        if rsp.misc_chassis_state.drive_fault:
            self.chassis_state.append('drive_fault')
        if rsp.misc_chassis_state.cooling_fault_detected:
            self.chassis_state.append('cooling_fault')

    def __str__(self):
        out = "Current Power State =>\n"
        out += "  power_on: {}\n".format(self.power_on)
        out += "  overload: {}\n".format(self.overload)
        out += "  interlock: {}\n".format(self.interlock)
        out += "  power fault: {}\n".format(self.fault)
        out += "  control fault: {}\n".format(self.control_fault)
        out += "  restore_policy: {}\n".format(self.restore_policy)
        out += "last event: {}\n".format(self.last_event)
        out += "Misc state {}\n".format(self.chassis_state)
        out += "id_cmd_state_info_support: {}\n".format(self.id_cmd_state_info_support)
        if self.id_cmd_state_info_support:
            out += "chassis_id_state: {}\n".format(self.chassis_id_state)

        return out








