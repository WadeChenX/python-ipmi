Transport Commands
====================

These commands are primarily to provide standardized transport device status and control functions for Remote Management Cards and Remote Consoles that access the :abbr:`BMC (Board Management Controller)`. The `IPMI standard`_ defines the following Chassis commands:

+---------------------------------------+-----+---------+-----+
| Command                               | O/M | Support | API |
+=======================================+=====+=========+=====+
| Get SOL Configuration Parameters      | O   | No      | Yes |
+---------------------------------------+-----+---------+-----+
| Set SOL Configuration Parameters      | O   | No      | Yes |
+---------------------------------------+-----+---------+-----+

.. note::
 
   - O/M - Optional/Mandatory command as stated by the IPMI standard
   - Support - Supported command by **send_message_with_name** method
   - API - High level API support implemented in this library

Get SOL Configuration Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This command is used for retrieving the configuration parameters from the *Set SOL Configuration Parameters* .

+-------------------------------------+
| **get_sol_info(channel=0)**         |
+-------------------------------------+

Optionally assign channel number, and get the returned object *SolInfo* back.

Where the returned object has the following attributes shown in the order as they appear in the table of the `IPMI standard`_:

  * set_in_progress
  * enable
  * privilege
  * force_payload_auth
  * force_payload_encrypt
  * char_accumulate_interval
  * char_send_threshold
  * retry_count
  * retry_interval
  * nonvolatile_bit_rate
  * volatile_bit_rate
  * payload_channel
  * payload_port

The returned object also could be dumped directly. For example:

.. code:: python

        sol_info = ipmi.get_sol_info(channel=0x0e)
        print(sol_info)


The output may be showed below:

.. code::

        enable=True
        privilege=user
        payload_port=623
        retry_interval=50
        payload_channel=1
        set_in_progress=set_complete
        char_send_threshold=96
        nonvolatile_bit_rate=115200
        volatile_bit_rate=115200
        force_payload_encrypt=False
        force_payload_auth=False
        char_accumulate_interval=12
        retry_count=7


Set SOL Configuration Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This command is used for setting parameters such as the network addressing information required for SOL payload operation. 

+-------------------------------------------+
| **set_sol_info(sol_info, channel=0)**     |
+-------------------------------------------+

Assign *sol_info* previous modified to apply SOL settings. For example:

.. code:: python

        sol_info = ipmi.get_sol_info(channel=0x0e)
        sol_info.enable = True
        sol_info.retry_interval = 51
        sol_info.nonvolatile_bit_rate = 57600
        sol_info.volatile_bit_rate = 57600
        sol_info.retry_count = 8
        ipmi.set_sol_info(sol_info, channel=0x0e)

.. note::

        Some fields may be **Read Only** . (eg: **payload_channel** and **payload_port**). See `IPMI standard`_



.. _IPMI standard: https://www.intel.com/content/dam/www/public/us/en/documents/product-briefs/ipmi-second-gen-interface-spec-v2-rev1-1.pdf
