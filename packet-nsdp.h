/* packet-nsdp.h
 * Definitions for Netgear Switch Discovery Protocol structures and routines
 * By Kevin Amiraux
 * Copyright 2015 Kevin Amiraux
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NSDP_PORT 63322
#define NSDP_HEADER_LEN 32

#define OP_DEVICE_MODEL 0x0001
#define OP_DEVICE_GIVEN_NAME 0x0003
#define OP_DEVICE_MAC_ADDRESS 0x0004
#define OP_DEVICE_IP_ADDRESS 0x0006
#define OP_DEVICE_IP_NETWORK_MASK 0x0007
#define OP_ROUTER_IP_ADDRESS 0x0008
#define OP_NEW_ADMINISTRATION_PASSWORD 0x0009
#define OP_ADMINISTRATION_PASSWORD 0x000a
#define OP_DHCP_STATUS 0x000b
#define OP_DEVICE_FIRMWARE_VERSION 0x000d
#define OP_REBOOT 0x0013
#define OP_FACTORY_RESET 0x0400
#define OP_SPEED_LINK_STATUS 0x0c00
#define OP_PORT_TRAFFIC_STATISTICS 0x1000
#define OP_RESET_PORT_TRAFFIC_STATISTICS 0x1400
#define OP_TEST_CABLE_REQUEST 0x1800
#define OP_TEST_CABLE_RESULT 0x1c00
#define OP_VLAN_ENGINE 0x2000
#define OP_PORT_BASED_VLAN_CONFIG 0x2400
#define OP_DOT1Q_PORT_MEMBERSHIP 0x2800
#define OP_DELETE_VLAN 0x2c00
#define OP_DOT1Q_DEFAULT_VLAN 0x3000
#define OP_QOS_ENGINE 0x3400
#define OP_PORT_BASED_QOS_PRIORITY 0x3800
#define OP_INGRESS_BANDWIDTH_LIMIT 0x4c00
#define OP_EGRESS_BANDWIDTH_LIMIT 0x5000
#define OP_BROADCAST_FILTERING 0x5400
#define OP_BROADCAST_BANDWIDTH 0x5800
#define OP_PORT_MIRRORING 0x5c00
#define OP_AVAILABLE_PORTS 0x6000
#define OP_IGMP_SNOOPING_STATUS 0x6800
#define OP_BLOCK_UNKNOWN_MULTICAST_TRAFFIC 0x6c00
#define OP_IGMPV3_IP_HEADER_VALIDATION 0x7000
#define OP_IGMP_SNOOPING_STATIC_ROUTER_PORTS 0x8000
#define OP_LOOP_DETECTION 0x9000
#define OP_EOM 0xffff
