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

SOL_PARAMETER_SET_IN_PROGRESS = 0
SOL_PARAMETER_ENABLE = 1
SOL_PARAMETER_AUTHENTICATION = 2
SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD = 3
SOL_PARAMETER_RETRY = 4
SOL_PARAMETER_NONVOLATILE_BIT_RATE = 5
SOL_PARAMETER_VOLATILE_BIT_RATE = 6
SOL_PARAMETER_PAYLOAD_CHANNEL = 7
SOL_PARAMETER_PAYLOAD_PORT = 8



@register_message_class
class SetSOLConfigurationParametersReq(Message):
    __cmdid__ = constants.CMDID_SET_SOL_CONFIGURATION_PATAMETERS
    __netfn__ = constants.NETFN_TRANSPORT

    def _cond_validate(self, expec_param):
        return self.parameter_selector == expec_param

    __fields__ = (
        Bitfield('command', 1,
                 Bitfield.Bit('channel_number', 4, 0),
                 Bitfield.ReservedBit(4, 0),),
        UnsignedInt('parameter_selector', 1),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_SET_IN_PROGRESS),
                     Bitfield('set_in_progress', 1,
                              Bitfield.Bit('status', 2, 0),
                              Bitfield.ReservedBit(6, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_ENABLE),
                     Bitfield('sol_enable', 1,
                              Bitfield.Bit('enable', 1, 0),
                              Bitfield.ReservedBit(7, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_AUTHENTICATION),
                     Bitfield('sol_auth', 1,
                              Bitfield.Bit('privilege', 4, 0),
                              Bitfield.ReservedBit(2, 0),
                              Bitfield.Bit('force_payload_auth', 1, 0),
                              Bitfield.Bit('force_payload_encrypt', 1, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD),
                     Bitfield('sol_char', 2,
                              Bitfield.Bit('accumulate_interval', 8, 0),
                              Bitfield.Bit('send_threshold', 8, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_RETRY),
                     Bitfield('retry', 2,
                              Bitfield.Bit('count', 3, 0),
                              Bitfield.ReservedBit(5, 0),
                              Bitfield.Bit('interval', 8, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_NONVOLATILE_BIT_RATE),
                     Bitfield('nonvolatile_bit_rate', 1,
                              Bitfield.Bit('bit_rate', 4, 0),
                              Bitfield.ReservedBit(4, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_VOLATILE_BIT_RATE),
                     Bitfield('volatile_bit_rate', 1,
                              Bitfield.Bit('bit_rate', 4, 0),
                              Bitfield.ReservedBit(4, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_PAYLOAD_CHANNEL),
                     UnsignedInt('payload_channel', 1)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_PAYLOAD_PORT),
                     UnsignedInt('payload_port', 2)),
    )


@register_message_class
class SetSOLConfigurationParametersRsp(Message):
    __cmdid__ = constants.CMDID_SET_SOL_CONFIGURATION_PATAMETERS
    __netfn__ = constants.NETFN_TRANSPORT | 1
    __fields__ = (
        CompletionCode(),
        Optional(ByteArray('auxiliary', 4))
    )


@register_message_class
class GetSOLConfigurationParametersReq(Message):
    __cmdid__ = constants.CMDID_GET_SOL_CONFIGURATION_PATAMETERS
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
class GetSOLConfigurationParametersRsp(Message):
    __cmdid__ = constants.CMDID_GET_SOL_CONFIGURATION_PATAMETERS
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
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_SET_IN_PROGRESS),
                     Bitfield('set_in_progress', 1,
                              Bitfield.Bit('status', 2, 0),
                              Bitfield.ReservedBit(6, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_ENABLE),
                     Bitfield('sol_enable', 1,
                              Bitfield.Bit('enable', 1, 0),
                              Bitfield.ReservedBit(7, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_AUTHENTICATION),
                     Bitfield('sol_auth', 1,
                              Bitfield.Bit('privilege', 4, 0),
                              Bitfield.ReservedBit(2, 0),
                              Bitfield.Bit('force_payload_auth', 1, 0),
                              Bitfield.Bit('force_payload_encrypt', 1, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_CHAR_INTERVAL_THRESHOLD),
                     Bitfield('sol_char', 2,
                              Bitfield.Bit('accumulate_interval', 8, 0),
                              Bitfield.Bit('send_threshold', 8, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_RETRY),
                     Bitfield('retry', 2,
                              Bitfield.Bit('count', 3, 0),
                              Bitfield.ReservedBit(5, 0),
                              Bitfield.Bit('interval', 8, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_NONVOLATILE_BIT_RATE),
                     Bitfield('nonvolatile_bit_rate', 1,
                              Bitfield.Bit('bit_rate', 4, 0),
                              Bitfield.ReservedBit(4, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_VOLATILE_BIT_RATE),
                     Bitfield('volatile_bit_rate', 1,
                              Bitfield.Bit('bit_rate', 4, 0),
                              Bitfield.ReservedBit(4, 0),)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_PAYLOAD_CHANNEL),
                     UnsignedInt('payload_channel', 1)),
        Conditional( lambda m: m._cond_validate(SOL_PARAMETER_PAYLOAD_PORT),
                     UnsignedInt('payload_port', 2)),
    )

