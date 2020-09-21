Transport Commands
====================

These commands are primarily to provide standardized transport device status and control functions for Remote Management Cards and Remote Consoles that access the :abbr:`BMC (Board Management Controller)`. The `IPMI standard`_ defines the following Chassis commands:

+---------------------------------------+-----+---------+-----+
| Command                               | O/M | Support | API |
+=======================================+=====+=========+=====+
| Get LAN Configuration Parameters      | O   | No      | Yes |
+---------------------------------------+-----+---------+-----+
| Set LAN Configuration Parameters      | O   | No      | Yes |
+---------------------------------------+-----+---------+-----+
| Get SOL Configuration Parameters      | O   | No      | Yes |
+---------------------------------------+-----+---------+-----+
| Set SOL Configuration Parameters      | O   | No      | Yes |
+---------------------------------------+-----+---------+-----+

.. note::
 
   - O/M - Optional/Mandatory command as stated by the IPMI standard
   - Support - Supported command by **send_message_with_name** method
   - API - High level API support implemented in this library

Get LAN Configuration Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This command is used for retrieving the configuration parameters from *Set LAN Configuration Parameters* command.

+-------------------------------------------------------+
| **get_lan_info(channel=0, info_type="ipv4")**         |
+-------------------------------------------------------+

Optionally assign **channel** as channel number and **info_type** as information type. Then get the returned object **LanInfo** back.

The argument **info_type** can take the following string to indicate information type:

 - ipv4
 - ipv6
 - all

Of course, the default is ``ipv4`` .


The returned object ``LanInfo`` has properties showed below:

  - set_in_progress
  - ipv4_address
  - ipv4_address_source
  - ipv4_subnet_mask
  - ipv4_default_gateway_address
  - ipv6_ipv4_addressing_enables
  - ipv6_static_selector
  - ipv6_static_address_source
  - ipv6_static_address
  - ipv6_static_prefix_length
  - ipv6_static_address_status
  - ipv6_dynamic_selector
  - ipv6_dynamic_address_source
  - ipv6_dynamic_address
  - ipv6_dynamic_prefix_length
  - ipv6_dynamic_address_status
  - ipv6_cur_selector
  - ipv6_cur_address_source
  - ipv6_cur_address
  - ipv6_cur_prefix_length
  - ipv6_cur_address_status

For more clear about these fields, refer to `IPMI standard`_


.. note::

        Address fields (eg: ipv4_address, ipv4_default_gateway_address, ipv6_cur_address...) could be identified or indicated easily by ``ipaddress`` python module.


The example code to get LAN information:

.. code:: python

        lan_info = ipmi.get_lan_info(channel=0x01, info_type="all")
        print(lan_info)

The output may be showed below:

.. code::

        ipv6_cur_selector=0
        ipv6_cur_address_source=DHCPv6
        ipv4_address=192.168.1.105
        ipv4_address_source=dhcp
        ipv4_default_gateway_address=192.168.1.1
        ipv4_subnet_mask=255.255.255.0
        ipv6_cur_address=::
        ipv6_dynamic_address_source=DHCPv6
        set_in_progress=set_complete
        ipv6_cur_address_status=active
        ipv6_static_selector=0
        ipv6_dynamic_address=::
        ipv6_ipv4_addressing_enables=ipv6_ipv4_addr_enabled
        ipv6_dynamic_selector=0
        ipv6_dynamic_prefix_length=0
        ipv6_dynamic_address_status=active
        ipv6_static_address=::
        ipv6_static_address_source=disable
        ipv6_static_prefix_length=0
        ipv6_cur_prefix_length=0
        ipv6_static_address_status=active


Set LAN Configuration Parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This command is used for setting parameters such as the network addressing information required for IPMI LAN operation.

.. |br| raw:: html

        <br/>

+----------------------------------+
| set_lan_info(channel=0,     |br| |
|       ipv4_enable=None,     |br| |
|       addr_src=None,        |br| |
|       addr=None,            |br| |
|       subnet_mask=None,     |br| |
|       gateway=None,         |br| |
|       ipv6_enable=None,     |br| |
|       v6_addr_src=None,     |br| |
|       v6_addr=None,         |br| |
|       v6_prefix_length=None)     |
+----------------------------------+

where

    - channel=0

        This is the channel number that communicate with BMC.

    - ipv4_enable=None

        | ``True`` if you need to configure IPv4 relative parameters.
        | ``False`` to disable IPv4.
        | ``None`` as previous configuration. 

    - addr_src=None

        | ``static_addr_by_manual`` for manually configuring. 
        | ``dhcp`` for the address obtained from DHCP. 
        | ``static_addr_by_bios_sw`` for the address obtained from BIOS or system software. 
        | ``static_addr_by_others`` for the address obtained other assigning protocol.

    - addr=None

        | Integer for IPv4 address. Could be easily managed by python ``ipaddress`` package.
        | ``None`` for previous configuration.

    - subnet_mask=None

        | Subnet mask. Could be easily managed by python ``ipaddress`` package.
        | ``None`` for previous configuration.

    - getway=None

        | Default gateway. Could be easily managed by python ``ipaddress`` package.
        | ``None`` for previous configuration.

    - ipv6_enable=None

        | ``True`` if you need to configure IPv6 relative parameters.
        | ``False`` to disable IPv6.
        | ``None`` for previous configuration.

    - v6_addr_src=None

        | ``ipv6_static_addr`` for static address srouce.
        | ``ipv6_dynamic`` for dynamic address but procotol choosed by BMC.
        | ``None`` for previous configuration.

    - v6_addr=None

        | Integer for IPv6 address. Could be easily managed by python ``ipaddress`` package.

    - v6_prefix_length=None

        | Integer for address prefix length.

.. note:: 

        If configuring from DHCP to static address but without configuring other parameterss (eg: address, netmask, gateway ...), all configuring from DHCP settings.

The example code to set LAN information:

.. code:: python

        ipmi.set_lan_info(channel=1, ipv4_enable=True, addr_src="static_addr_by_manual",  addr=ipaddress.IPv4Address("192.168.1.105"))



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
