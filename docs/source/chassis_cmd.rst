Chassis Commands
================

These commands are primarily to provide standardized chassis status and control functions for Remote Management Cards and Remote Consoles that access the :abbr:`BMC (Board Management Controller)`. The `IPMI standard`_ defines the following Chassis commands:

+-------------------------------+-----+---------+-----+
| Command                       | O/M | Support | API |
+===============================+=====+=========+=====+
| Get Chassis Capabilities      | M   | Yes     | No  |
+-------------------------------+-----+---------+-----+
| Get Chassis Status            | M   | Yes     | Yes |
+-------------------------------+-----+---------+-----+
| Chassis Control               | M   | Yes     | Yes |
+-------------------------------+-----+---------+-----+
| Chassis Reset                 | O   | No      | No  |
+-------------------------------+-----+---------+-----+
| Chassis Identify              | O   | No      | Yes |
+-------------------------------+-----+---------+-----+
| Set Front Panel Enables       | O   | No      | No  |
+-------------------------------+-----+---------+-----+
| Set Chassis Capabilities      | O   | No      | No  |
+-------------------------------+-----+---------+-----+
| Set Power Restore Policy      | O   | No      | No  |
+-------------------------------+-----+---------+-----+
| Set Power Cycle Interval      | O   | No      | No  |
+-------------------------------+-----+---------+-----+
| Get System Restart Cause      | O   | No      | No  |
+-------------------------------+-----+---------+-----+
| Set System Boot Options       | O   | No      | No  |
+-------------------------------+-----+---------+-----+
| Get System Boot Options       | O   | No      | No  |
+-------------------------------+-----+---------+-----+
| Get POH Counter               | O   | Yes     | No  |
+-------------------------------+-----+---------+-----+

.. note::
 
   - O/M - Optional/Mandatory command as stated by the IPMI standard
   - Support - Supported command by **send_message_with_name** method
   - API - High level API support implemented in this library

Get Chassis Capabilities Command
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This command returns information about which main chassis management functions are present on the :abbr:`IPMB (Intelligent Platform Management Bus)` and what addresses are used to access those functions. This command is used to find the devices that provide functions such as :abbr:`SEL (System Event Log)`, :abbr:`SDR (Snesor Data Record)`, and :abbr:`ICMB (Intelligent Chassis Management Bus)` Bridging so that theyt can be accessed via commands delivered via a physical or logical :abbr:`IPMB (Intelligent Platform Management Bus)`.

+-------------------------------------+
| **get_chassis_capabilities()**      |
+-------------------------------------+

**NOT IMPLEMENTED YET!!!**

Get Chassis Status Command
~~~~~~~~~~~~~~~~~~~~~~~~~~

This command returns information regarding the high-level status of the system chassis and main power subsystem.

+--------------------------------------+
| **get_chassis_status()**             |
+--------------------------------------+

where the returned object has the following attributes shown in the order as they appear in the table of the `IPMI standard`_:

  * ``restore_policy``
  * ``control_fault``
  * ``fault``
  * ``interlock``
  * ``overload``
  * ``power_on``
  * ``last_event``
  * ``chassis_state``

For example:

.. code:: python

   chassis_status=ipmi.get_chassis_status()
   print(chassis_status)

The output showed as below:

.. code::

        power_on=False
        overload=False
        interlock=False
        fault=False
        control_fault=False
        restore_policy=power_on
        last event=['ac_failed']
        chassis_state=[]
        id_cmd_state_info_support=True
        chassis_id_state=off


.. |br| raw:: html

        <br/>

Chassis Status Monitor Command 
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This command is used to wait specific property value to become the value of ``to_value`` .

+--------------------------------------+
|    chassis_watch(             |br|   |
|        field,                 |br|   |
|        to_value,              |br|   |
|        from_value=None,       |br|   |
|        timeout=0,             |br|   |
|        interval=0.5)                 |
+--------------------------------------+


where

    - field

        The field of ``ChassisStatus``.

    - to_value

        | The value that the field of ``SolInfo`` would become to.
        | The type of ``to_value`` is depend on the value type of the field.

    - from_value=None

        | The value that the field of ChassisStatus start.
        | If it's ``None`` , then skip to check.
        | The type of ``from_value`` is depend on the value type of the field.

    - timeout=0

        | ``-1`` means infinite wait.
        | ``0`` means check once.
        | ``value > 0`` means timeout value

    - interval=0.5

        The unit time to wait and then check. MUST >= 0.5.

return value showed below:

    - WATCH_STATE_TIMEOUT = -1
    - WATCH_STATE_COMPLETE = 0
    - WATCH_STATE_INIT = 1
    - WATCH_STATE_WAIT_FROM_VAL = 2
    - WATCH_STATE_WAIT_TO_VAL = 3

Example code showed below:

.. code:: python

        ret = ipmi.chassis_watch("power_on", True, timeout=2)
        if ret == ipmi.WATCH_STATE_TIMEOUT:
            print("timeout")


Chassis Control Command
~~~~~~~~~~~~~~~~~~~~~~~

This command provides a mechanism for providing power up, power down, and reset control.

+-----------------------------------------+
| **chassis_control(option)**             |
+-----------------------------------------+

where the ``option`` argument can take the following integer values as defined in the standard:

 - CONTROL_POWER_DOWN = 0
 - CONTROL_POWER_UP = 1
 - CONTROL_POWER_CYCLE = 2
 - CONTROL_HARD_RESET = 3
 - CONTROL_DIAGNOSTIC_INTERRUPT = 4
 - CONTROL_SOFT_SHUTDOWN = 5


For example:

.. code:: python

   ipmi.chassis_control(option)

There are methods defined for each of the above options:

.. code:: python

   ipmi.chassis_control_power_down()
   ipmi.chassis_control_power_up()
   ipmi.chassis_control_power_cycle()
   ipmi.chassis_control_hard_reset()
   ipmi.chassis_control_diagnostic_interrupt()
   ipmi.chassis_control_soft_shutdown()


Chassis Identify
~~~~~~~~~~~~~~~~~

This command causes the chassis to physically identify itself by a mechanism chosen by the system implementation, 
such as turning on blinking user-visible lights or emitting beeps via a beeper, LCD panel, etc.

+-----------------------------------------+
| **chassis_turn_id(state, value=0)**     |
+-----------------------------------------+

where ``state`` argument can take the following string as defined below:

 - off
 - interval_on
 - on

if state is "interval_on", then ``value`` could be assigned as timeout value.


.. _IPMI standard: https://www.intel.com/content/dam/www/public/us/en/documents/product-briefs/ipmi-second-gen-interface-spec-v2-rev1-1.pdf
