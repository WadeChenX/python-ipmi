from __future__ import absolute_import
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

from . import constants
from . import register_message_class
from . import Message
from . import ByteArray
from . import UnsignedInt
from . import UnsignedIntBig
from . import Bitfield
from . import CompletionCode
from . import Optional
from . import Conditional
from . import RemainingBytes
from ..errors import (CompletionCodeError, EncodingError, DecodingError,
                      DescriptionError, NotSupportedError)

LAN_PARAMETER_SET_IN_PROGRESS = 0
LAN_PARAMETER_AUTHENTICATION_TYPE_SUPPORT = 1
LAN_PARAMETER_AUTHENTICATION_TYPE_ENABLE = 2
LAN_PARAMETER_IP_ADDRESS = 3
LAN_PARAMETER_IP_ADDRESS_SOURCE = 4
LAN_PARAMETER_MAC_ADDRESS = 5
LAN_PARAMETER_SUBNET_MASK = 6
LAN_PARAMETER_IPV4_HEADER_PARAMETERS = 7
LAN_PARAMETER_PRIMARY_RMCP_PORT = 8
LAN_PARAMETER_SECONDARY_RMCP_PORT = 9
LAN_PARAMETER_BMC_GENERATED_ARP_CONTROL = 10
LAN_PARAMETER_GRATUITOUS_ARP_INTERVAL = 11
LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS = 12
LAN_PARAMETER_DEFAULT_GATEWAY_MAC_ADDRESS = 13
LAN_PARAMETER_BACKUP_GATEWAY_ADDRESS = 14
LAN_PARAMETER_BACKUP_GATEWAY_MAC_ADDRESS = 15
LAN_PARAMETER_COMMUNITY_STRING = 16
LAN_PARAMETER_NUMBER_OF_DESTINATIONS = 17
LAN_PARAMETER_DESTINATION_TYPE = 18
LAN_PARAMETER_DESTINATION_ADDRESSES = 19
# following parameters are introduced with IPMI v2.0/RMCP+
LAN_PARAMETER_802_1Q_VLAN_ID = 20
LAN_PARAMETER_802_1Q_VLAN_PRIORITY = 21
LAN_PARAMETER_RMCP_PLUS_MESSAGING_CIPHER_SUITE_ENTRY_SUPPORT = 22
LAN_PARAMETER_RMCP_PLUS__MESSAGING_CIPHER_SUITE_ENTRIES = 23
LAN_PARAMETER_RMCP_PLUS_MESSAGING_CIPHER_SUITE_PRIVILEGE_LEVES = 24
LAN_PARAMETER_DESTINATION_ADDRESS_VLAN_TAGS = 25

LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES = 51
LAN_PARAMETER_IPV6_STATIC_ADDRESSES = 56
LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS = 59

LAN_PARAMETER_IP_ADDRESS_SOURCE_UNSPECIFIED = 0
LAN_PARAMETER_IP_ADDRESS_SOURCE_STATIC = 1
LAN_PARAMETER_IP_ADDRESS_SOURCE_DHCP = 2
LAN_PARAMETER_IP_ADDRESS_SOURCE_BIOS_OR_SYSTEM_SOFTWARE = 3
LAN_PARAMETER_IP_ADDRESS_SOURCE_BMC_OTHER_PROTOCOL = 4


@register_message_class
class SetLanConfigurationParametersReq(Message):
    __cmdid__ = constants.CMDID_SET_LAN_CONFIGURATION_PARAMETERS
    __netfn__ = constants.NETFN_TRANSPORT

    def _cond_validate(self, expec_param):
        return self.parameter_selector == expec_param

    __fields__ = (
        Bitfield('command', 1,
                 Bitfield.Bit('channel_number', 4, 0),
                 Bitfield.ReservedBit(4, 0),),
        UnsignedInt('parameter_selector', 1),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IP_ADDRESS),
                     UnsignedIntBig('ipv4_address', 4)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IP_ADDRESS_SOURCE),
                     Bitfield('ipv4_address_source', 1,
                              Bitfield.Bit('src', 4, 0),
                              Bitfield.ReservedBit(4, 0),)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_SUBNET_MASK),
                     UnsignedIntBig('ipv4_subnet_mask', 4)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS),
                     UnsignedIntBig('ipv4_default_gateway_address', 4)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES),
                     UnsignedInt('ipv6_ipv4_addressing_enables', 1)),
        #IPv6 static address
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     UnsignedIntBig('ipv6_static_selector', 1)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     Bitfield('ipv6_static_address_source', 1,
                              Bitfield.Bit('src', 4, 0),
                              Bitfield.ReservedBit(3, 0),
                              Bitfield.Bit('enable', 1, 0),)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     UnsignedIntBig('ipv6_static_address', 16)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     UnsignedIntBig('ipv6_static_prefix_length', 1)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     UnsignedIntBig('ipv6_static_address_status', 1)),
        #IPv6 dynamic address
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     UnsignedIntBig('ipv6_dynamic_selector', 1)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     Bitfield('ipv6_dynamic_address_source', 1,
                              Bitfield.Bit('src', 4, 0),
                              Bitfield.ReservedBit(4, 0),)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     UnsignedIntBig('ipv6_dynamic_address', 16)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     UnsignedInt('ipv6_dynamic_prefix_length', 1)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     UnsignedInt('ipv6_dynamic_address_status', 1)),
    )


@register_message_class
class SetLanConfigurationParametersRsp(Message):
    __cmdid__ = constants.CMDID_SET_LAN_CONFIGURATION_PARAMETERS
    __netfn__ = constants.NETFN_TRANSPORT | 1
    __fields__ = (
        CompletionCode(),
        Optional(ByteArray('auxiliary', 4))
    )


@register_message_class
class GetLanConfigurationParametersReq(Message):
    __cmdid__ = constants.CMDID_GET_LAN_CONFIGURATION_PARAMETERS
    __netfn__ = constants.NETFN_TRANSPORT
    __fields__ = (
        Bitfield('command', 1,
                 Bitfield.Bit('channel_number', 4),
                 Bitfield.ReservedBit(3, 0),
                 Bitfield.Bit('get_parameter_revision_only', 1, 0),),
        UnsignedInt('parameter_selector', 1, 0),
        UnsignedInt('set_selector', 1, 0),
        UnsignedInt('block_selector', 1, 0),
    )


@register_message_class
class GetLanConfigurationParametersRsp(Message):
    __cmdid__ = constants.CMDID_GET_LAN_CONFIGURATION_PARAMETERS
    __netfn__ = constants.NETFN_TRANSPORT | 1

    def _cond_validate(self, expec_param):
        rsp = self
        req = self.req_obj
        if req is None:
            raise NotSupportedError()

        return req.command.get_parameter_revision_only == 0 and req.parameter_selector == expec_param

    __fields__ = (
        CompletionCode(),
        UnsignedInt('parameter_revision', 1, 0),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_SET_IN_PROGRESS),
                     Bitfield('set_in_progress', 1,
                              Bitfield.Bit('status', 2, 0),
                              Bitfield.ReservedBit(6, 0),)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IP_ADDRESS),
                     UnsignedIntBig('ipv4_address', 4)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IP_ADDRESS_SOURCE),
                     Bitfield('ipv4_address_source', 1,
                              Bitfield.Bit('src', 4, 0),
                              Bitfield.ReservedBit(4, 0),)),

        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_SUBNET_MASK),
                     UnsignedIntBig('ipv4_subnet_mask', 4)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_DEFAULT_GATEWAY_ADDRESS),
                     UnsignedIntBig('ipv4_default_gateway_address', 4)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_IPV4_ADDRESSING_ENABLES),
                     UnsignedInt('ipv6_ipv4_addressing_enables', 1)),
        #IPv6 static address
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     UnsignedIntBig('ipv6_static_selector', 1)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     Bitfield('ipv6_static_address_source', 1,
                              Bitfield.Bit('src', 4, 0),
                              Bitfield.ReservedBit(3, 0),
                              Bitfield.Bit('enable', 1, 0),)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     UnsignedIntBig('ipv6_static_address', 16)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     UnsignedInt('ipv6_static_prefix_length', 1)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_STATIC_ADDRESSES),
                     UnsignedInt('ipv6_static_address_status', 1)),
        #IPv6 dynamic address
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     UnsignedIntBig('ipv6_dynamic_selector', 1)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     Bitfield('ipv6_dynamic_address_source', 1,
                              Bitfield.Bit('src', 4, 0),
                              Bitfield.ReservedBit(4, 0),)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     UnsignedIntBig('ipv6_dynamic_address', 16)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     UnsignedInt('ipv6_dynamic_prefix_length', 1)),
        Conditional( lambda m: m._cond_validate(LAN_PARAMETER_IPV6_DYNAMIC_ADDRESS),
                     UnsignedInt('ipv6_dynamic_address_status', 1)),
    )

