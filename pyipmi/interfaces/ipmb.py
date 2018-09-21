# Copyright (c) 2015  Kontron Europe GmbH
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

import array

from ..logger import log
from ..msgs import create_message, create_request_by_name, \
        encode_message, decode_message, constants
from ..utils import check_completion_code


def checksum(data):
    csum = 0
    for b in data:
        csum += b
    return -csum % 256


class IpmbHeader(object):
    def __init__(self):
        self.rs_sa = None
        self.rs_lun = None
        self.rq_sa = None
        self.rq_lun = None
        self.rq_seq = None
        self.netfn = None
        self.cmd_id = None

    def encode(self):
        data = array.array('B')
        data.append(self.rs_sa)
        data.append(self.netfn << 2 | self.rs_lun)
        data.append(checksum((self.rs_sa, data[1])))
        data.append(self.rq_sa)
        data.append(self.rq_seq << 2 | self.rq_lun)
        data.append(self.cmd_id)
        return data


def encode_ipmb_msg(header, data):
    if type(data) == str:
        data = [ord(c) for c in data]
    msg = header.encode()
    msg.extend(data)
    msg.append(checksum(msg[3:]))
    return msg.tostring()


def encode_send_message(payload, rq_sa, rs_sa, channel, seq, tracking=1):
        req = create_request_by_name('SendMessage')
        req.channel.number = channel
        req.channel.tracking = tracking
        header = IpmbHeader()
        header.netfn = req.__netfn__
        header.rs_lun = 0
        header.rs_sa = rs_sa
        header.rq_seq = seq
        header.rq_lun = 0
        header.rq_sa = rq_sa
        header.cmd_id = req.__cmdid__
        data = encode_message(req)
        return encode_ipmb_msg(header, data + payload)


def encode_bridged_message(routing, header, payload, seq):
    if len(routing) < 2:
        raise EncodingError('routing length error')

    # change header requester addresses for bridging
    header.rq_sa = routing[-1].rq_sa
    header.rs_sa = routing[-1].rs_sa
    tx_data = encode_ipmb_msg(header, payload)

    for r in reversed(routing[:-1]):
        tx_data = encode_send_message(tx_data, rq_sa=r.rq_sa, rs_sa=r.rs_sa,
                                      channel=r.channel, seq=seq)

    return tx_data


def decode_bridged_message(rx_data):
    while rx_data[5] == constants.CMDID_SEND_MESSAGE:
        rsp = create_message(constants.CMDID_SEND_MESSAGE,
                             constants.NETFN_APP+1)
        decode_message(rsp, rx_data[6:])
        check_completion_code(rsp.completion_code,
                              cmd_id=constants.CMDID_SEND_MESSAGE)
        rx_data = rx_data[7:-1]

        if len(rx_data) < 6:
            break
    return rx_data


def rx_filter(header, rx_data):
    if type(rx_data) == str:
        rx_data = array.array('B', rx_data)

    checks = [
        (checksum(rx_data[0:3]), 0, 'Header checksum failed'),
        (checksum(rx_data[3:]), 0, 'payload checksum failed'),
        # (rx_data[0], header.rq_sa, 'slave address mismatch'),
        (rx_data[1] & ~3, header.netfn << 2 | 4, 'NetFn mismatch'),
        # (rx_data[3], header.rs_sa, 'target address mismatch'),
        # (rx_data[1] & 3, header.rq_lun, 'request LUN mismatch'),
        (rx_data[4] & 3, header.rs_lun & 3, 'responder LUN mismatch'),
        (rx_data[4] >> 2, header.rq_seq, 'sequence number mismatch'),
        (rx_data[5], header.cmd_id, 'command id mismatch'),
    ]

    match = True

    for left, right, msg in checks:
        if left != right:
            log().debug('%s: %s %s' % (msg, left, right))
            match = False

    return match
