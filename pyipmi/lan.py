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
from .msgs import lan
from .errors import NotSupportedError

class Lan(object):
    def get_lan_config_param(self, channel=0, parameter_selector=0,
                             set_selector=0, block_selector=0,
                             revision_only=0):
        req = create_request_by_name('GetLanConfigurationParameters')
        req.command.get_parameter_revision_only = revision_only
        if revision_only != 1:
            req.command.channel_number = channel
            req.parameter_selector = parameter_selector
            req.set_selector = set_selector
            req.block_selector = block_selector
        rsp = self.send_message(req)
        check_completion_code(rsp.completion_code)
        return rsp.data

    def _lan_send_and_recv(self, reqs):
        rsp_list = []
        for r in reqs:
            rsp = self.send_message(r)
            check_completion_code(rsp.completion_code)

            rsp_list.append(rsp)

        return rsp_list

    def __lan_new_get_req(self, channel, parameter_selector, set_selector=0, block_selector=0):
        req = create_request_by_name('GetLanConfigurationParameters')
        req.command.channel_number = channel
        req.set_selector = set_selector
        req.block_selector = block_selector
        req.parameter_selector = parameter_selector

        return req


    def get_lan_info(self, channel=0, info_type="ipv4"):
        lan_info = LanInfo()

        group_ipv4_ipv6 = False
        group_ipv4 = False
        group_ipv6 = False
        if info_type == "all":
            group_ipv4_ipv6 = group_ipv4 = group_ipv6 = True
        elif info_type == "ipv4":
            group_ipv4_ipv6 = group_ipv4 = True
        elif info_type == "ipv6":
            group_ipv4_ipv6 = group_ipv6 = True
        else:
            raise NotSupportedError()

        req_list = []
        req_list.append(self.__lan_new_get_req(channel, lan.LAN_PARAMETER_SET_IN_PROGRESS))
        if group_ipv4_ipv6:
            req_list.append(self.__lan_new_get_req(channel, lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES))

        if group_ipv4:
            req_list.append(self.__lan_new_get_req(channel, lan.LAN_PARAMETER_IP_ADDRESS))
            req_list.append(self.__lan_new_get_req(channel, lan.LAN_PARAMETER_IP_ADDRESS_SOURCE))
            req_list.append(self.__lan_new_get_req(channel, lan.LAN_PARAMETER_SUBNET_MASK))
            req_list.append(self.__lan_new_get_req(channel, lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS))

        if group_ipv6:
            req_list.append(self.__lan_new_get_req(channel, lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES))
            req_list.append(self.__lan_new_get_req(channel, lan.LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS))

        rsp_list = self._lan_send_and_recv(req_list)
        for rsp in rsp_list:
            lan_info.refresh_info(rsp)

        if group_ipv6:
            lan_info._refresh_ipv6_info()

        return lan_info

    def prepare_lan_info_ipv4_ipv6(self,
            lan_info,
            channel=0,
            ipv4_enable=None,
            ipv6_enable=None):

        """
        ===============================================================================
        current state           | ipv4_enable | ipv6_enable | next state
        ===============================================================================
        ipv6_addr_disabled      | True        |  True       | ipv6_ipv4_addr_enabled
        ipv6_addr_disabled      | True        |  False      | (NO CHANGE) 
        ipv6_addr_disabled      | True        |  None       | (NO CHANGE) 
        ipv6_addr_disabled      | False       |  True       | ipv6_addr_enable_only
        ipv6_addr_disabled      | False       |  False      | (NOT SUPPORT)
        ipv6_addr_disabled      | False       |  None       | (NOT SUPPORT)
        ipv6_addr_disabled      | None        |  True       | ipv6_ipv4_addr_enabled
        ipv6_addr_disabled      | None        |  False      | (NO CHANGE) 
        ipv6_addr_disabled      | None        |  None       | (NOT SUPPORT)
        ipv6_addr_enable_only   | True        |  True       | ipv6_ipv4_addr_enabled
        ipv6_addr_enable_only   | True        |  False      | ipv6_addr_disabled
        ipv6_addr_enable_only   | True        |  None       | ipv6_ipv4_addr_enabled
        ipv6_addr_enable_only   | False       |  True       | (NO CHANGE)  
        ipv6_addr_enable_only   | False       |  False      | (NOT SUPPORT)
        ipv6_addr_enable_only   | False       |  None       | (NO CHANGE)  
        ipv6_addr_enable_only   | None        |  True       | (NO CHANGE)  
        ipv6_addr_enable_only   | None        |  False      | (NOT SUPPORT)
        ipv6_addr_enable_only   | None        |  None       | (NOT SUPPORT)
        ipv6_ipv4_addr_enabled  | True        |  True       | (NO CHANGE)    
        ipv6_ipv4_addr_enabled  | True        |  False      | ipv6_addr_disabled
        ipv6_ipv4_addr_enabled  | True        |  None       | (NO CHANGE)
        ipv6_ipv4_addr_enabled  | False       |  True       | ipv6_addr_enable_only
        ipv6_ipv4_addr_enabled  | False       |  False      | (NOT SUPPORT)
        ipv6_ipv4_addr_enabled  | False       |  None       | ipv6_addr_enable_only
        ipv6_ipv4_addr_enabled  | None        |  True       | (NO CHANGE)
        ipv6_ipv4_addr_enabled  | None        |  False      | ipv6_addr_disabled
        ipv6_ipv4_addr_enabled  | None        |  None       | (NOT SUPPORT)
        """

        state_map = [
                ["ipv6_addr_disabled", True, True, "ipv6_ipv4_addr_enabled"],
                ["ipv6_addr_disabled", True, False, "NO CHANGE"],
                ["ipv6_addr_disabled", True, None, "NO CHANGE"],
                ["ipv6_addr_disabled", False, True, "ipv6_addr_enable_only"],
                ["ipv6_addr_disabled", False, False, "NOT SUPPORT"],
                ["ipv6_addr_disabled", False, None, "NOT SUPPORT"],
                ["ipv6_addr_disabled", None, True, "ipv6_ipv4_addr_enabled"],
                ["ipv6_addr_disabled", None, False, "NO CHANGE"],
                ["ipv6_addr_disabled", None, None, "NOT SUPPORT"],
                ["ipv6_addr_enable_only", True, True, "ipv6_ipv4_addr_enabled"],
                ["ipv6_addr_enable_only", True, False, "ipv6_addr_disabled"],
                ["ipv6_addr_enable_only", True, None, "ipv6_ipv4_addr_enabled"],
                ["ipv6_addr_enable_only", False, True, "NO CHANGE"],
                ["ipv6_addr_enable_only", False, False, "NOT SUPPORT"],
                ["ipv6_addr_enable_only", False, None, "NO CHANGE"],
                ["ipv6_addr_enable_only", None, True, "NO CHANGE"],
                ["ipv6_addr_enable_only", None, False, "NOT SUPPORT"],
                ["ipv6_addr_enable_only", None, None, "NOT SUPPORT"],
                ["ipv6_ipv4_addr_enabled", True, True, "NO CHANGE"],
                ["ipv6_ipv4_addr_enabled", True, False, "ipv6_addr_disabled"],
                ["ipv6_ipv4_addr_enabled", True, None, "NO CHANGE"],
                ["ipv6_ipv4_addr_enabled", False, True, "ipv6_addr_enable_only"],
                ["ipv6_ipv4_addr_enabled", False, False, "NOT SUPPORT"],
                ["ipv6_ipv4_addr_enabled", False, None, "ipv6_addr_enable_only"],
                ["ipv6_ipv4_addr_enabled", None, True, "NO CHANGE"],
                ["ipv6_ipv4_addr_enabled", None, False, "ipv6_addr_disabled"],
                ["ipv6_ipv4_addr_enabled", None, None, "NOT SUPPORT"],
            ]

        req_list = []
        req = create_request_by_name('SetLanConfigurationParameters')
        req.command.channel_number = channel
        req.parameter_selector = lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES
        for item_list in state_map:
            cur_state = item_list[0]
            ipv4 = item_list[1]
            ipv6 = item_list[2]
            next_state = item_list[3]

            if lan_info.ipv6_ipv4_addressing_enables == cur_state and ipv4_enable == ipv4 and ipv6_enable == ipv6:
                if next_state == "NO CHANGE":
                    next_state = cur_state
                    break
                elif next_state == "NOT SUPPORT":
                    raise NotSupportedError()
                else:
                    req.ipv6_ipv4_addressing_enables = LanInfo.FIELD_IPV6_IPV4_ADDRESSING_ENABLES_INV[next_state]
                    req_list.append(req)

        return req_list, next_state


    def prepare_lan_info_ipv4(self, 
            lan_info,
            channel=0, 
            ipv4_enable=True, 
            addr_src=None, 
            addr=None, 
            subnet_mask=None, 
            gateway=None):
        # Check parameters correction
        params = [addr_src, addr, subnet_mask, gateway]
        params_valid = [ x for x in params if x is not None ]
        if ipv4_enable is False:
            if len(params_valid) > 0:
                raise RuntimeError("Disable ipv4, other parameters SHOULD NOT be given.")

            return []

        if len(params_valid) == 0:
            raise RuntimeError("Enable ipv4 MUST be given one of field: addr/subnet_mask/gateway")

        # prepare set requests
        req_list = []

        req = create_request_by_name('SetLanConfigurationParameters')
        req.command.channel_number = channel
        req.parameter_selector = lan.LAN_PARAMETER_IP_ADDRESS_SOURCE
        if addr_src is not None:
            if addr_src not in LanInfo.FIELD_IP_ADDRESS_SOURCE_INV.keys():
                raise RuntimeError("Can't find {} in maps.".format(addr_src))
            req.ipv4_address_source = LanInfo.FIELD_IP_ADDRESS_SOURCE_INV[addr_src]

        else:
            req.ipv4_address_source = LanInfo.FIELD_IP_ADDRESS_SOURCE_INV["static_addr_by_manual"]
        req_list.append(req)

        if req.ipv4_address_source != LanInfo.FIELD_IP_ADDRESS_SOURCE_INV["dhcp"]:
            req = create_request_by_name('SetLanConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = lan.LAN_PARAMETER_IP_ADDRESS
            if addr is None:
                addr = lan_info.ipv4_address
            elif type(addr) is not ipaddress.IPv4Address:
                raise RuntimeError("parameter 'addr' is not type of ipaddress.IPv4Address")
            req.ipv4_address = int(addr)
            req_list.append(req)

            req = create_request_by_name('SetLanConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = lan.LAN_PARAMETER_SUBNET_MASK
            if subnet_mask is None:
                subnet_mask = lan_info.ipv4_subnet_mask
            elif type(subnet_mask) is not ipaddress.IPv4Address:
                raise RuntimeError("parameter 'subnet_mask' is not type of ipaddress.IPv4Address")
            req.ipv4_subnet_mask = int(subnet_mask)
            req_list.append(req)

            req = create_request_by_name('SetLanConfigurationParameters')
            req.command.channel_number = channel
            req.parameter_selector = lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS
            if gateway is None:
                gateway = lan_info.ipv4_default_gateway_address
            elif type(gateway) is not ipaddress.IPv4Address:
                raise RuntimeError("parameter 'gateway' is not type of ipaddress.IPv4Address")
            req.ipv4_default_gateway_address = int(gateway)
            req_list.append(req)

        return req_list


    def prepare_lan_info_ipv6(self, 
            lan_info,
            channel=0, 
            ipv6_enable=None, 
            v6_selector=None, 
            v6_addr_src=None, 
            v6_addr=None, 
            v6_prefix_length=None):

        params = [v6_selector, v6_addr_src, v6_addr, v6_prefix_length]
        params_valid = [ x for x in params if x is not None ]
        if ipv6_enable is False:
            if len(params_valid) > 0:
                raise RuntimeError("Disable ipv6, other parameters SHOULD NOT be given.")

            return []

        if len(params_valid) == 0:
            raise RuntimeError("Enable ipv6 MUST be given one of field: addr/subnet_mask/gateway")

        # prepare set requests
        req_list = []

        if v6_selector is None:
            v6_selector = lan_info.ipv6_static_selector
        elif type(v6_selector) != int or v6_selector > 255:
            raise RuntimeError("parameter 'v6_selector' is not 'int' type or 'v6_selector' > 255")

        if v6_addr_src is None:
            v6_addr_src = lan_info.ipv6_static_address_source
        elif v6_addr_src not in LanInfo.FIELD_IPV6_ADDRESS_SOURCE_INV.keys():
            raise RuntimeError("parameter 'v6_addr_src' incorrect: {}".format(v6_addr_src))

        if v6_addr is None:
            v6_addr = lan_info.ipv6_cur_address
        elif type(v6_addr) is not ipaddress.IPv6Address:
            raise RuntimeError("parameter 'v6_addr' is not type of ipaddress.IPv6Address")

        if v6_prefix_length is None:
            v6_prefix_length = lan_info.ipv6_cur_prefix_length
        elif type(v6_prefix_length) != int or v6_prefix_length > 255:
            raise RuntimeError("parameter 'v6_prefix_length' is not 'int' type or 'v6_prefix_length' > 255")


        req = create_request_by_name('SetLanConfigurationParameters')
        req.command.channel_number = channel
        req.parameter_selector = lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES
        req.ipv6_static_selector = v6_selector
        if v6_addr_src == "DHCPv6":
            req.ipv6_static_address_source.src = 0
            req.ipv6_static_address_source.enable = 0
            req.ipv6_static_address = 0
            req.ipv6_static_prefix_length = 0
            req.ipv6_static_address_status = 0
        else:
            req.ipv6_static_address_source.src = LanInfo.FIELD_IPV6_ADDRESS_SOURCE_INV[v6_addr_src]
            req.ipv6_static_address_source.enable = 1
            req.ipv6_static_address = int(v6_addr)
            req.ipv6_static_prefix_length = v6_prefix_length
            req.ipv6_static_address_status = 0

        req_list.append(req)

        return req_list

    def set_lan_info(self, 
            channel=0, 
            ipv4_enable=None, 
            addr_src=None, 
            addr=None, 
            subnet_mask=None, 
            gateway=None,
            ipv6_enable=None,
            v6_addr_src=None,
            v6_selector=None,
            v6_addr=None,
            v6_prefix_length=None):

        if ipv4_enable is False and ipv6_enable is False:
            raise RuntimeError("ERROR: IPv4/IPv6 are all disabled")


        ipv4_dict = dict(
                ipv4_enable=ipv4_enable,
                addr_src=addr_src,
                addr=addr,
                subnet_mask=subnet_mask,
                gateway=gateway,
            )
        ipv4_dict_input = {k:v for k,v in ipv4_dict.items() if v is not None}
        if ipv4_enable in ipv4_dict_input and len(ipv4_dict_input) == 1:
            raise RuntimeError("Lack of other ipv4 fields")

        ipv6_dict = dict(
                ipv6_enable=ipv6_enable,
                v6_addr_src=v6_addr_src,
                v6_selector=v6_selector,
                v6_addr=v6_addr,
                v6_prefix_length=v6_prefix_length
            )
        ipv6_dict_input = {k:v for k,v in ipv6_dict.items() if v is not None}
        if ipv6_enable in ipv6_dict_input and len(ipv6_dict_input) == 1:
            raise RuntimeError("Lack of other ipv6 fields")

        if len(ipv4_dict_input) == 0 and len(ipv6_dict_input) == 0:
            raise RuntimeError("Lack of parameters") 

        if len(ipv4_dict_input) > 0 and len(ipv6_dict_input) > 0:
            info_type="all"
        elif len(ipv4_dict_input) > 0:
            info_type="ipv4"
        elif len(ipv6_dict_input) > 0:
            info_type="ipv6"
        else:
            raise NotSupportedError()

        lan_info = self.get_lan_info(channel, info_type=info_type)
        req_list, next_state = self.prepare_lan_info_ipv4_ipv6(lan_info, channel=channel, ipv4_enable=ipv4_enable, ipv6_enable=ipv6_enable)
        if next_state != "ipv6_addr_enable_only" and len(ipv4_dict_input) > 0:
            req_list += self.prepare_lan_info_ipv4(lan_info, channel=channel, **ipv4_dict_input)
        if next_state != "ipv6_addr_disabled" and len(ipv6_dict_input) > 0:
            req_list += self.prepare_lan_info_ipv6(lan_info, channel=channel, **ipv6_dict_input)

        rsp_list = self._lan_send_and_recv(req_list)


    def set_lan_config_param(self, channel,
                             parameter_selector, data):
        req = create_request_by_name('SetLanConfigurationParameters')
        req.command.channel_number = channel
        req.parameter_selector = parameter_selector
        req.data = data
        rsp = self.send_message(req)
        check_completion_code(rsp.completion_code)


class LanInfo(object):
    FIELDS_DEF_VALUE = {
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

    def __str__(self):
        result=""
        for k, v in LanInfo.FIELDS_DEF_VALUE.items():
            result += "{}={}\n".format(k, getattr(self, k))

        return result


    def clear_info(self):
        for k, v in LanInfo.FIELDS_DEF_VALUE.items():
            setattr(self, k , v)

    def __init__(self):
        self.clear_info()

    def _refresh_ipv6_info(self):
        """ 
        Call this function after sending LAN_PARAMETER_IPV6_STATIC_ADDRESSES, LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS
        """
        #update combine field
        if self.ipv6_static_address_source == "ipv6_static_addr":
            self.ipv6_cur_selector = self.ipv6_static_selector
            self.ipv6_cur_address_source = self.ipv6_static_address_source
            self.ipv6_cur_address = self.ipv6_static_address
            self.ipv6_cur_prefix_length = self.ipv6_static_prefix_length
            self.ipv6_cur_address_status = self.ipv6_static_address_status

        elif self.ipv6_static_address_source == "disable":
            if self.ipv6_dynamic_address_source == "SLAAC" or self.ipv6_dynamic_address_source == "DHCPv6":
                self.ipv6_cur_selector = self.ipv6_dynamic_selector
                self.ipv6_cur_address_source = self.ipv6_dynamic_address_source
                self.ipv6_cur_address = self.ipv6_dynamic_address
                self.ipv6_cur_prefix_length = self.ipv6_dynamic_prefix_length
                self.ipv6_cur_address_status = self.ipv6_dynamic_address_status

            else:
                self.ipv6_cur_selector = None
                self.ipv6_cur_address_source = None
                self.ipv6_cur_address = None
                self.ipv6_cur_prefix_length = None
                self.ipv6_cur_address_status = None

    FIELD_SET_IN_PROGRESS = {
            0: "set_complete",
            1: "set_in_progress",
            2: "commit_write",
            3: "reserved",
    }
    FIELD_SET_IN_PROGRESS_INV = {v:k for k, v in FIELD_SET_IN_PROGRESS.items()}


    FIELD_IP_ADDRESS_SOURCE = {
            0: "unspecified",
            1: "static_addr_by_manual",
            2: "dhcp",
            3: "static_addr_by_bios_sw",
            4: "static_addr_by_others",
    }
    FIELD_IP_ADDRESS_SOURCE_INV = {v:k for k, v in FIELD_IP_ADDRESS_SOURCE.items()}

    FIELD_IPV6_IPV4_ADDRESSING_ENABLES = {
            0: "ipv6_addr_disabled",
            1: "ipv6_addr_enable_only",
            2: "ipv6_ipv4_addr_enabled",
    }
    FIELD_IPV6_IPV4_ADDRESSING_ENABLES_INV = {v:k for k, v in FIELD_IPV6_IPV4_ADDRESSING_ENABLES.items()}

    FIELD_IPV6_ADDRESS_SOURCE = {
            0: "ipv6_static_addr",
            1: "SLAAC",
            2: "DHCPv6",
    }
    FIELD_IPV6_ADDRESS_SOURCE_INV = { v:k for k, v in FIELD_IPV6_ADDRESS_SOURCE.items() }

    FIELD_IPV6_ADDRESSES_STS = {
            0: "active",
            1: "disabled",
            2: "pending",
            3: "failed",
            4: "deprecated",
            5: "invalid",
    }
    FIELD_IPV6_ADDRESSES_STS_INV = {v:k for k, v in FIELD_IPV6_ADDRESSES_STS.items()}

    def refresh_info(self, rsp):
        req = rsp.req_obj
        if req is None:
            raise RuntimeError("Can't find request obj in response.")

        if req.parameter_selector == lan.LAN_PARAMETER_SET_IN_PROGRESS:
            self.set_in_progress = LanInfo.FIELD_SET_IN_PROGRESS[rsp.set_in_progress.status]

        elif req.parameter_selector == lan.LAN_PARAMETER_IP_ADDRESS:
            self.ipv4_address = ipaddress.IPv4Address(rsp.ipv4_address)

        elif req.parameter_selector == lan.LAN_PARAMETER_IP_ADDRESS_SOURCE:
            self.ipv4_address_source = LanInfo.FIELD_IP_ADDRESS_SOURCE[rsp.ipv4_address_source.src]

        elif req.parameter_selector == lan.LAN_PARAMETER_SUBNET_MASK:
            self.ipv4_subnet_mask = ipaddress.IPv4Address(rsp.ipv4_subnet_mask)

        elif req.parameter_selector == lan.LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS:
            self.ipv4_default_gateway_address = ipaddress.IPv4Address(rsp.ipv4_default_gateway_address)

        elif req.parameter_selector == lan.LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES:
            self.ipv6_ipv4_addressing_enables = LanInfo.FIELD_IPV6_IPV4_ADDRESSING_ENABLES[rsp.ipv6_ipv4_addressing_enables]

        elif req.parameter_selector == lan.LAN_PARAMETER_IPV6_STATIC_ADDRESSES:
            self.ipv6_static_selector = rsp.ipv6_static_selector

            if rsp.ipv6_static_address_source.enable == 0:
                self.ipv6_static_address_source = "disable"
            elif rsp.ipv6_static_address_source.src not in LanInfo.FIELD_IPV6_ADDRESS_SOURCE.keys():
                self.ipv6_static_address_source = "reversed" 
            else:
                self.ipv6_static_address_source = LanInfo.FIELD_IPV6_ADDRESS_SOURCE[rsp.ipv6_static_address_source.src]

            self.ipv6_static_address = ipaddress.IPv6Address(rsp.ipv6_static_address)
            self.ipv6_static_prefix_length = rsp.ipv6_static_prefix_length
            if rsp.ipv6_static_address_status not in LanInfo.FIELD_IPV6_ADDRESSES_STS.keys():
                self.ipv6_static_address_status = "reserved"
            else:
                self.ipv6_static_address_status = LanInfo.FIELD_IPV6_ADDRESSES_STS[rsp.ipv6_static_address_status]

        elif req.parameter_selector == lan.LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS:
            self.ipv6_dynamic_selector = rsp.ipv6_dynamic_selector

            if rsp.ipv6_dynamic_address_source.src not in LanInfo.FIELD_IPV6_ADDRESS_SOURCE.keys():
                self.ipv6_dynamic_address_source = "reserved"
            else:
                self.ipv6_dynamic_address_source = LanInfo.FIELD_IPV6_ADDRESS_SOURCE[rsp.ipv6_dynamic_address_source.src]

            self.ipv6_dynamic_address = ipaddress.IPv6Address(rsp.ipv6_dynamic_address)
            self.ipv6_dynamic_prefix_length = rsp.ipv6_dynamic_prefix_length

            if rsp.ipv6_dynamic_address_status not in LanInfo.FIELD_IPV6_ADDRESS_SOURCE.keys():
                self.ipv6_dynamic_address_status = "reserved"
            else:
                self.ipv6_dynamic_address_status = LanInfo.FIELD_IPV6_ADDRESSES_STS[rsp.ipv6_dynamic_address_status]


