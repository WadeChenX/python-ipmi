
from __future__ import absolute_import

from .msgs import create_request_by_name
from .utils import check_completion_code
from .state import State
from .errors import NotSupportedError

import time

class Base(object):
    WATCH_STATE_TIMEOUT = -1
    WATCH_STATE_COMPLETE = 0
    WATCH_STATE_INIT = 1
    WATCH_STATE_WAIT_FROM_VAL = 2
    WATCH_STATE_WAIT_TO_VAL = 3

    def watch(self, get_func, field, to_value, from_value=None, timeout=0, interval=0.5):

        if timeout < -1:
            raise NotSupportedError("timeout MUST >= -1")

        if interval < 0.5:
            raise NotSupportedError("interval MUST >= 0.5")

        is_infinite = False
        if timeout < 0:
            is_infinite = True

        t_unit = 0
        state = Base.WATCH_STATE_INIT
        while t_unit < timeout or is_infinite:
            if state == Base.WATCH_STATE_INIT:
                state = Base.WATCH_STATE_WAIT_FROM_VAL

            data_obj = get_func()
            value = getattr(data_obj, field)
            if state == Base.WATCH_STATE_WAIT_FROM_VAL:
                if from_value is None: 
                    state = Base.WATCH_STATE_WAIT_TO_VAL
                elif value == from_value:
                    state = Base.WATCH_STATE_WAIT_TO_VAL
                    continue

            if state == Base.WATCH_STATE_WAIT_TO_VAL:
                if value == to_value:
                    state = Base.WATCH_STATE_COMPLETE
                    break

            time.sleep(interval)
            t_unit += interval

        if state != Base.WATCH_STATE_COMPLETE:
            state = Base.WATCH_STATE_TIMEOUT

        return state
