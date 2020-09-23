
from __future__ import absolute_import

from .msgs import create_request_by_name
from .utils import check_completion_code
from .state import State
from .errors import NotSupportedError

import time

class Base(object):
    STATE_TIMEOUT = -1
    STATE_COMPLETE = 0
    STATE_INIT = 1
    STATE_WAIT_FROM_VAL = 2
    STATE_WAIT_TO_VAL = 3

    def watch(self, get_func, field, to_value, from_value=None, timeout=0, interval=0.5):

        if timeout < -1:
            raise NotSupportedError("timeout MUST >= -1")

        if interval < 0.5:
            raise NotSupportedError("interval MUST >= 0.5")

        is_infinite = False
        if timeout < 0:
            is_infinite = True

        t_unit = 0
        state = Base.STATE_INIT
        while t_unit < timeout or is_infinite:
            if state == Base.STATE_INIT:
                state = Base.STATE_WAIT_FROM_VAL

            data_obj = get_func()
            value = getattr(data_obj, field)
            if state == Base.STATE_WAIT_FROM_VAL:
                if from_value is None: 
                    state = Base.STATE_WAIT_TO_VAL
                elif value == from_value:
                    state = Base.STATE_WAIT_TO_VAL
                    continue

            if state == Base.STATE_WAIT_TO_VAL:
                if value == to_value:
                    state = Base.STATE_COMPLETE
                    break

            time.sleep(interval)
            t_unit += interval

        if state != Base.STATE_COMPLETE:
            state = Base.STATE_TIMEOUT

        return state
