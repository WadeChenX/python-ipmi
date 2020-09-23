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

import ipaddress

from .msgs import create_request_by_name
from .utils import check_completion_code
from .msgs import sol
from .errors import NotSupportedError
from .base import Base

class Sol(Base):

    def _sol_send_and_recv(self, reqs):
        rsp_list = []
        for r in reqs:
            rsp = self.send_message(r)
            check_completion_code(rsp.completion_code)

            rsp_list.append(rsp)

        return rsp_list

    def __sol_new_get_req(self, channel, parameter_selector, set_selector=0, block_selector=0):
        req = create_request_by_name('GetSOLConfigurationParameters')
        req.command.channel_number = channel
        req.parameter_selector = parameter_selector
        req.set_selector = set_selector
        req.block_selector = block_selector

        return req


    def get_sol_info(self, channel=0):
        sol_info = SolInfo()

        req_list = []
        req_list.append(self.__sol_new_get_req(channel, sol.SOL_PARAMETER_SET_IN_PROGRESS))
        req_list.append(self.__sol_new_get_req(channel, sol.SOL_PARAMETER_ENABLE))
        req_list.append(self.__sol_new_get_req(channel, sol.SOL_PARAMETER_AUTHENTICATION))
        req_list.append(self.__sol_new_get_req(channel, sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD))
        req_list.append(self.__sol_new_get_req(channel, sol.SOL_PARAMETER_RETRY))
        req_list.append(self.__sol_new_get_req(channel, sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE))
        req_list.append(self.__sol_new_get_req(channel, sol.SOL_PARAMETER_VOLATILE_BIT_RATE))
        req_list.append(self.__sol_new_get_req(channel, sol.SOL_PARAMETER_PAYLOAD_CHANNEL))
        req_list.append(self.__sol_new_get_req(channel, sol.SOL_PARAMETER_PAYLOAD_PORT))

        rsp_list = self._sol_send_and_recv(req_list)
        for rsp in rsp_list:
            sol_info.refresh_info(rsp)

        return sol_info

    def set_sol_info(self, sol_info, channel=0):

        req_list = []
        rsp_list = []

        if isinstance(sol_info, SolInfo) is False:
            raise RuntimeError("ERROR: Invalid type")

        is_modified = sol_info.is_modified()

        # SOL_PARAMETER_SET_IN_PROGRESS (in progress)
        if is_modified:
            req = create_request_by_name('SetSOLConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = sol.SOL_PARAMETER_SET_IN_PROGRESS
            req.set_in_progress.status = SolInfo.FIELD_SET_IN_PROGRESS_INV["set_in_progress"]
            req_list.append(req)

        # SOL_PARAMETER_ENABLE
        if sol_info.is_modified(sol.SOL_PARAMETER_ENABLE):
            req = create_request_by_name('SetSOLConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = sol.SOL_PARAMETER_ENABLE
            req.sol_enable.enable = 1 if sol_info.enable is True else 0
            req_list.append(req)

        # SOL_PARAMETER_AUTHENTICATION
        if sol_info.is_modified(sol.SOL_PARAMETER_AUTHENTICATION):
            req = create_request_by_name('SetSOLConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = sol.SOL_PARAMETER_AUTHENTICATION
            req.sol_auth.privilege = SolInfo.FIELD_PRIVILEDGE_LEVEL_INV[sol_info.privilege]
            req.sol_auth.force_payload_auth = 1 if sol_info.force_payload_auth is True else 0
            req.sol_auth.force_payload_encrypt = 1 if sol_info.force_payload_encrypt is True else 0
            req_list.append(req)

        # SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD
        if sol_info.is_modified(sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD):
            req = create_request_by_name('SetSOLConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD
            req.sol_char.accumulate_interval = sol_info.char_accumulate_interval
            req.sol_char.send_threshold = sol_info.char_send_threshold
            req_list.append(req)

        # SOL_PARAMETER_RETRY
        if sol_info.is_modified(sol.SOL_PARAMETER_RETRY):
            req = create_request_by_name('SetSOLConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = sol.SOL_PARAMETER_RETRY
            req.retry.count = sol_info.retry_count
            req.retry.interval = sol_info.retry_interval
            req_list.append(req)

        # SOL_PARAMETER_NONVOLATILE_BIT_RATE
        if sol_info.is_modified(sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE):
            req = create_request_by_name('SetSOLConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE
            req.nonvolatile_bit_rate.bit_rate = sol_info.nonvolatile_bit_rate
            req_list.append(req)

        # SOL_PARAMETER_VOLATILE_BIT_RATE
        if sol_info.is_modified(sol.SOL_PARAMETER_VOLATILE_BIT_RATE):
            req = create_request_by_name('SetSOLConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = sol.SOL_PARAMETER_VOLATILE_BIT_RATE
            req.volatile_bit_rate.bit_rate = sol_info.volatile_bit_rate
            req_list.append(req)

        # SOL_PARAMETER_SET_IN_PROGRESS (complete)
        if is_modified:
            req = create_request_by_name('SetSOLConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = sol.SOL_PARAMETER_SET_IN_PROGRESS
            req.set_in_progress.status = SolInfo.FIELD_SET_IN_PROGRESS_INV["set_complete"]
            req_list.append(req)

        if len(req_list) > 0:
            rsp_list = self._sol_send_and_recv(req_list)

    def sol_watch(self, field, to_value, from_value=None, timeout=0, interval=0.5, channel=0):
        return self.watch(lambda: self.get_sol_info(channel), field, to_value, from_value, timeout, interval)


class SolInfo(object):
    FIELDS_DEF_VALUE = {
            "_set_in_progress": None,
            "_enable": None,
            "_privilege": None,
            "_force_payload_auth": None,
            "_force_payload_encrypt": None,
            "_char_accumulate_interval": None,
            "_char_send_threshold": None,
            "_retry_count": None,
            "_retry_interval": None,
            "_nonvolatile_bit_rate": None,
            "_volatile_bit_rate": None,
            "_payload_channel": None,
            "_payload_port": None,
    }

    PARAM_FIELDS_MAP = {
            sol.SOL_PARAMETER_SET_IN_PROGRESS: (
                    "_set_in_progress",
                ),
            sol.SOL_PARAMETER_ENABLE: (
                    "_enable",
                ),
            sol.SOL_PARAMETER_AUTHENTICATION: (
                    "_privilege",
                    "_force_payload_auth",
                    "_force_payload_encrypt",
                ),
            sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD: (
                    "_char_accumulate_interval",
                    "_char_send_threshold",
                ),
            sol.SOL_PARAMETER_RETRY: (
                    "_retry_count",
                    "_retry_interval",
                ),
            sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE: (
                    "_nonvolatile_bit_rate",
                ),
            sol.SOL_PARAMETER_VOLATILE_BIT_RATE: (
                    "_volatile_bit_rate",
                ),
            sol.SOL_PARAMETER_PAYLOAD_CHANNEL: (
                    "_payload_channel",
                ),
            sol.SOL_PARAMETER_PAYLOAD_PORT: (
                    "_payload_port",
                ),
    }


    FIELD_SET_IN_PROGRESS = {
            0: "set_complete",
            1: "set_in_progress",
            2: "commit_write",
            3: "reserved",
    }
    FIELD_SET_IN_PROGRESS_INV = {v:k for k, v in FIELD_SET_IN_PROGRESS.items()}


    FIELD_PRIVILEDGE_LEVEL = {
            2: "user",
            3: "operator",
            4: "administrator",
    }
    FIELD_PRIVILEDGE_LEVEL_INV = {v:k for k, v in FIELD_PRIVILEDGE_LEVEL.items()}

    FIELD_BIT_RATE = {
            0: 0,
            6: 9600,
            7: 19200,
            8: 38400,
            9: 57600,
            10: 115200,
    }
    FIELD_BIT_RATE_INV = {v:k for k, v in FIELD_BIT_RATE.items()}

    @property
    def set_in_progress(self):
        return self._set_in_progress


    @property
    def enable(self):
        return self._enable
    @enable.setter
    def enable(self, value):
        if type(value) != bool:
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_enable'] = True
        self._enable = value

    @property
    def privilege(self):
        return self._privilege
    @privilege.setter
    def privilege(self, value):
        if value not in SolInfo.FIELD_PRIVILEDGE_LEVEL_INV.keys():
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_privilege'] = True
        self._privilege = value

    @property
    def force_payload_auth(self):
        return self._force_payload_auth
    @force_payload_auth.setter
    def force_payload_auth(self, value):
        if type(value) != bool:
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_force_payload_auth'] = True
        self._force_payload_auth = value


    @property
    def force_payload_encrypt(self):
        return self._force_payload_encrypt
    @force_payload_encrypt.setter
    def force_payload_encrypt(self, value):
        if type(value) != bool:
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_force_payload_encrypt'] = True
        self._force_payload_encrypt = value

    @property
    def char_accumulate_interval(self):
        return self._char_accumulate_interval

    @char_accumulate_interval.setter
    def char_accumulate_interval(self, value):
        if value > 255: # 1Byte max
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_char_accumulate_interval'] = True
        self._char_accumulate_interval = value


    @property
    def char_send_threshold(self):
        return self._char_send_threshold 
    @char_send_threshold.setter
    def char_send_threshold(self, value):
        if value > 255: # 1Byte max
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_char_send_threshold'] = True
        self._char_send_threshold = value


    @property
    def retry_count(self):
        return self._retry_count
    @retry_count.setter
    def retry_count(self, value):
        if value > (1<<3) - 1: # only 3bits
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_retry_count'] = True
        self._retry_count = value


    @property
    def retry_interval(self):
        return self._retry_interval
    @retry_interval.setter
    def retry_interval(self, value):
        if value > (1<<8) - 1: # 1Byte
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_retry_interval'] = True
        self._retry_interval = value


    @property
    def nonvolatile_bit_rate(self):
        return self._nonvolatile_bit_rate
    @nonvolatile_bit_rate.setter
    def nonvolatile_bit_rate(self, value):
        if value not in SolInfo.FIELD_BIT_RATE_INV.keys():
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_nonvolatile_bit_rate'] = True
        self._nonvolatile_bit_rate = SolInfo.FIELD_BIT_RATE_INV[value]


    @property
    def volatile_bit_rate(self):
        return self._volatile_bit_rate
    @volatile_bit_rate.setter
    def volatile_bit_rate(self, value):
        if value not in SolInfo.FIELD_BIT_RATE_INV.keys():
            raise NotSupportedError("'{}' not support".format(value))

        self.modify_flag['_volatile_bit_rate'] = True
        self._volatile_bit_rate = SolInfo.FIELD_BIT_RATE_INV[value]


    @property
    def payload_channel(self):
        return self._payload_channel


    @property
    def payload_port(self):
        return self._payload_port


    def __str__(self):
        result=""
        for k, v in SolInfo.FIELDS_DEF_VALUE.items():
            result += "{}={}\n".format(k[1:], getattr(self, k[1:]))

        return result


    def clear_info(self):
        for k, v in SolInfo.FIELDS_DEF_VALUE.items():
            setattr(self, k , v)
            self.modify_flag[k] = False

    def __init__(self):
        self.modify_flag = {}
        self.clear_info()

    def is_modified(self, param=None):
        if param is None:
            for k, v in self.modify_flag.items():
                if self.modify_flag[k]:
                    return True
            return False

        else:
            for field in SolInfo.PARAM_FIELDS_MAP[param]:
                if self.modify_flag[field]:
                    return True
            return False

        return False

    def refresh_info(self, rsp):
        req = rsp.req_obj
        if req is None:
            raise RuntimeError("Can't find request obj in response.")

        if req.parameter_selector == sol.SOL_PARAMETER_SET_IN_PROGRESS:
            self._set_in_progress = SolInfo.FIELD_SET_IN_PROGRESS[rsp.set_in_progress.status]
            self.modify_flag['_set_in_progress'] = False

        elif req.parameter_selector == sol.SOL_PARAMETER_ENABLE:
            self._enable = True  if rsp.sol_enable.enable == 1 else False
            self.modify_flag['_enable'] = False

        elif req.parameter_selector == sol.SOL_PARAMETER_AUTHENTICATION:
            self._privilege = SolInfo.FIELD_PRIVILEDGE_LEVEL[rsp.sol_auth.privilege]
            self._force_payload_auth = True if rsp.sol_auth.force_payload_auth == 1 else False
            self._force_payload_encrypt = True if rsp.sol_auth.force_payload_encrypt == 1 else False
            self.modify_flag['_privilege'] = False
            self.modify_flag['_force_payload_auth'] = False
            self.modify_flag['_force_payload_encrypt'] = False

        elif req.parameter_selector == sol.SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD:
            self._char_accumulate_interval = rsp.sol_char.accumulate_interval
            self._char_send_threshold = rsp.sol_char.send_threshold
            self.modify_flag['_accumulate_interval'] = False
            self.modify_flag['_send_threshold'] = False

        elif req.parameter_selector == sol.SOL_PARAMETER_RETRY:
            self._retry_count = rsp.retry.count
            self._retry_interval = rsp.retry.interval
            self.modify_flag['_retry_count'] = False
            self.modify_flag['_retry_interval'] = False

        elif req.parameter_selector == sol.SOL_PARAMETER_NONVOLATILE_BIT_RATE:
            self._nonvolatile_bit_rate = SolInfo.FIELD_BIT_RATE[rsp.nonvolatile_bit_rate.bit_rate]
            self.modify_flag['_nonvolatile_bit_rate'] = False

        elif req.parameter_selector == sol.SOL_PARAMETER_VOLATILE_BIT_RATE:
            self._volatile_bit_rate = SolInfo.FIELD_BIT_RATE[rsp.volatile_bit_rate.bit_rate]
            self.modify_flag['_volatile_bit_rate'] = False

        elif req.parameter_selector == sol.SOL_PARAMETER_PAYLOAD_CHANNEL:
            self._payload_channel = rsp.payload_channel
            self.modify_flag['_payload_channel'] = False

        elif req.parameter_selector == sol.SOL_PARAMETER_PAYLOAD_PORT:
            self._payload_port = rsp.payload_port
            self.modify_flag['_payload_port'] = False


