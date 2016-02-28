/* packet-nsdp.c
 * Routines for Netgear Switch Discovery Protocol
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

#include "config.h"

#include <epan/packet.h>
#include "packet-nsdp.h"

/*
 * See
 *
 *     https://en.wikipedia.org/wiki/Netgear_NSDP
 */

#define PORTX_BITFIELD_MASK( PORTNUM ) (1 << (8 - (PORTNUM)))

#define HF_PORT_STRUCT(PORTNUM)                                      \
    { &tlv_port ## PORTNUM ## inbitfield,                            \
        { "Port " #PORTNUM, "nsdp.body.tlv.portbitfield" #PORTNUM,   \
            FT_BOOLEAN, 8,                                           \
            NULL, PORTX_BITFIELD_MASK(((PORTNUM - 1) % 8) + 1),      \
            NULL, HFILL }                                            \
    }

void proto_register_nsdp(void);
void proto_reg_handoff_nsdp(void);

static int proto_nsdp = -1;
static gint ett_nsdp = -1;
static gint ett_nsdp_body = -1;
static gint ett_nsdp_body_tlv = -1;
static gint ett_nsdp_body_tlv_detail = -1;

static int hf_nsdp_version = -1;
static int hf_nsdp_opcode = -1;
static int hf_nsdp_opres = -1;
static int hf_nsdp_unknown1 = -1;
static int hf_nsdp_hostmac = -1;
static int hf_nsdp_netdevmac = -1;
static int hf_nsdp_unknown2 = -1;
static int hf_nsdp_seq = -1;
static int hf_nsdp_psig = -1;
static int hf_nsdp_unknown3 = -1;
static int nsdp_body = -1;
static int nsdp_body_tlv = -1;
static int nsdp_body_tlv_tag = -1;
static int nsdp_body_tlv_len = -1;
static int nsdp_body_tlv_valhex = -1;
static int nsdp_body_tlv_valstr = -1;
static int nsdp_body_tlv_valdetail = -1;

static int tlv_enable = -1;
static int tlv_vlanid = -1;
static int tlv_devip = -1;
static int tlv_devnetmask = -1;
static int tlv_routerip = -1;
static int tlv_portid = -1;
static int tlv_linkstatus = -1;
static int tlv_stat_rx_bytes = -1;
static int tlv_stat_tx_bytes = -1;
static int tlv_stat_crc_err = -1;
static int tlv_numport = -1;
static int tlv_testcableres = -1;
static int tlv_mirrordisabled = -1;
static int tlv_vlan_engine = -1;
static int tlv_qos_engine = -1;
static int tlv_qos_rate = -1;
static int tlv_qos_priority = -1;

static int tlv_port1inbitfield = -1;
static int tlv_port2inbitfield = -1;
static int tlv_port3inbitfield = -1;
static int tlv_port4inbitfield = -1;
static int tlv_port5inbitfield = -1;
static int tlv_port6inbitfield = -1;
static int tlv_port7inbitfield = -1;
static int tlv_port8inbitfield = -1;
static int tlv_port9inbitfield = -1;
static int tlv_port10inbitfield = -1;
static int tlv_port11inbitfield = -1;
static int tlv_port12inbitfield = -1;
static int tlv_port13inbitfield = -1;
static int tlv_port14inbitfield = -1;
static int tlv_port15inbitfield = -1;
static int tlv_port16inbitfield = -1;


static const value_string opcodenames[] = {
    { 1, "Read request" },
    { 2, "Read response" },
    { 3, "Write request" },
    { 4, "Write response" },
    { 0, NULL }
};

static const value_string operationresultnames[] = {
    { 0x0000, "Success" },
    { 0x0700, "Invalid password" },
    { 0, NULL }
};

static const value_string enablenames[] = {
    { 0x00, "Disable" },
    { 0x01, "Enable" },
    { 0x03, "Enable" }, // Storm control in enabled with 3...
    { 0, NULL }
};

static const value_string qosenginenames[] = {
    { 0x00, "Disabled" },
    { 0x01, "Port based" },
    { 0x02, "802.1p" },
    { 0, NULL }
};

static const value_string vlanenginenames[] = {
    { 0x00, "Disabled" },
    { 0x01, "Port based, basic (port can belong to at most 1 vlan)" },
    { 0x02, "Port based, advanced (port can belong to multiple vlans)" },
    { 0x03, "802.1q, basic (port can belong to at most 1 vlan)" },
    { 0x04, "802.1q, advanced (port can belong to multiple vlans, tagging, etc)" },
    { 0, NULL }
};

static const value_string qosprioritynames[] = {
    { 0x00, "Disabled" },
    { 0x01, "High priority" },
    { 0x02, "Medium priority" },
    { 0x03, "Normal" },
    { 0x04, "Low priority" },
    { 0, NULL }
};

static const value_string qosratenames[] = {
    { 0x00, "No limit" },
    { 0x01, "512 Kbps" },
    { 0x02, "1 Mbps" },
    { 0x03, "2 Mbps" },
    { 0x04, "4 Mbps" },
    { 0x05, "8 Mbps" },
    { 0x06, "16 Mbps" },
    { 0x07, "32 Mbps" },
    { 0x08, "64 Mbps" },
    { 0x09, "128 Mbps" },
    { 0x0a, "256 Mbps" },
    { 0x0b, "512 Mbps" },
    { 0, NULL }
};

static const value_string linkstatusnames[] = {
    { 0x00, "Down" },
    { 0x01, "10 Mbps half-duplex" },
    { 0x02, "10 Mbps full-duplex" },
    { 0x03, "100 Mbps half-duplex" },
    { 0x04, "100 Mbps full-duplex" },
    { 0x05, "1000 Mbps" },
    { 0, NULL }
};

static const value_string tagnames[] = {
    // General info
    { OP_DEVICE_MODEL, "Device model" },
    { OP_DEVICE_GIVEN_NAME, "Device given name" },

    // Network info
    { OP_DEVICE_MAC_ADDRESS, "Device MAC address" },
    { OP_DEVICE_IP_ADDRESS, "Device IP address" },
    { OP_DEVICE_IP_NETWORK_MASK, "Device IP network mask" },
    { OP_ROUTER_IP_ADDRESS, "Router IP address (gateway)" },

    // Admin
    { OP_NEW_ADMINISTRATION_PASSWORD, "New administration password" },
    { OP_ADMINISTRATION_PASSWORD, "Administration password" },
    { OP_DHCP_STATUS, "DHCP Status" },
    { OP_DEVICE_FIRMWARE_VERSION, "Device firmware version" },
    { OP_REBOOT, "Reboot" },
    { OP_FACTORY_RESET, "Factory Reset" },

    // Statistics/status
    { OP_SPEED_LINK_STATUS, "Speed/Link status" },
    { OP_PORT_TRAFFIC_STATISTICS, "Port traffic statistics" },
    { OP_RESET_PORT_TRAFFIC_STATISTICS, "Reset port traffic statistics" },
    { OP_TEST_CABLE_REQUEST, "Test cable request" },
    { OP_TEST_CABLE_RESULT, "Test cable result" },

    // Vlan configuration
    // basic/advanced port based, basic/advanced 802.1q
    { OP_VLAN_ENGINE, "VLAN Engine" },
    // 2 bytes = vlanId, 1-X bytes port bitfield
    { OP_PORT_BASED_VLAN_CONFIG, "Port based VLAN config" },
    { OP_DOT1Q_PORT_MEMBERSHIP, "802.1q Port membership" },
    { OP_DELETE_VLAN, "Delete VLAN" },
    { OP_DOT1Q_DEFAULT_VLAN, "802.1q default vlan (PVID)" },

    // Qos
    { OP_QOS_ENGINE, "QOS engine" }, // 1 = port based; 2 = 802.1p
    // 1 byte port; 1 byte priority (1 = high, 2 = medium, 3 = normal, 4 = low)
    { OP_PORT_BASED_QOS_PRIORITY, "Port based QOS - priority" },
    // 1 byte port, 2 bytes, 2 bytes bandwidth
    // 0x0 No limit
    // 0x1 512 Kbps
    // 0x2 1 Mbps
    // 0x3 2 Mbps
    // 0x4 4 Mbps
    // 0x5 8 Mbps
    // 0x6 16 Mbps
    // 0x7 32 Mbps
    // 0x8 64 Mbps
    // 0x9 128 Mbps
    // 0xa 256 Mbps
    // 0xb 512 Mbps
    { OP_INGRESS_BANDWIDTH_LIMIT, "Ingress bandwidth limit" },
    { OP_EGRESS_BANDWIDTH_LIMIT, "Egress bandwidth limit" }, // same
    // 1 byte (0 = dis, 3 = en)
    { OP_BROADCAST_FILTERING, "Broadcast filtering (storm control)" },
    { OP_BROADCAST_BANDWIDTH, "Broadcast bandwidth (storm control)" }, // same

    // Mirroring
    // 1 byte = destination port, 2 bytes source port bitfield
    { OP_PORT_MIRRORING, "Port mirroring" },
    { OP_AVAILABLE_PORTS, "Available ports" },

    // Multicast/IGMP
     // 1 byte == 00, 1 byte = 0/1, 2 bytes vlanId
    { OP_IGMP_SNOOPING_STATUS, "IGMP Snooping status" },
    // 1 byte = 0/1
    { OP_BLOCK_UNKNOWN_MULTICAST_TRAFFIC, "Block unknown multicast traffic" },
    // 1 byte = 0/1
    { OP_IGMPV3_IP_HEADER_VALIDATION, "IGMPv3 IP header validation" },
    // 2 bytes: port bitfield
    { OP_IGMP_SNOOPING_STATIC_ROUTER_PORTS, "IGMP Snooping static router ports" },

    { OP_LOOP_DETECTION, "Loop detection" }, // 1 byte = 0/1

    { OP_EOM, "End Of Message" },
    { 0, NULL }
};

typedef void (*dissect_value_detail_handler)(tvbuff_t *tvb, proto_tree *tree,
                                             gint offset, gint tlv_len,
                                             const void *data);

// Helpers for TLV dissection

// Generic dissectors

// Enable disable
static void
dissect_value_enable_disable(tvbuff_t *tvb, proto_tree *tree,
                             gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 1)
        return;
    proto_tree_add_item(tree, tlv_enable, tvb, offset,
                        1, ENC_BIG_ENDIAN);
}

// Mac address
static void
dissect_value_mac(tvbuff_t *tvb, proto_tree *tree,
                  gint offset, gint tlv_len, const void *data)
{
    if (tlv_len < 6)
        return;
    proto_tree_add_item(tree, *(int*)data, tvb, offset,
                        6, ENC_BIG_ENDIAN);
}

// IP address
static void
dissect_value_ip(tvbuff_t *tvb, proto_tree *tree,
                 gint offset, gint tlv_len, const void *data)
{
    if (tlv_len < 4)
        return;
    proto_tree_add_item(tree, *(int*)data, tvb, offset,
                        4, ENC_BIG_ENDIAN);
}

// Port Id
static void
dissect_port_id(tvbuff_t *tvb, proto_tree *tree,
                gint offset, gint tlv_len, const void *data)
{
    const char *str = (const char*)data;
    proto_item *ti = NULL;
    if (tlv_len < 1)
        return;
    ti = proto_tree_add_item(tree, tlv_portid, tvb, offset,
                             1, ENC_BIG_ENDIAN);
    if (str)
        proto_item_append_text(ti, " %s", str);
}

// Vlan Id
static void
dissect_vlan_id(tvbuff_t *tvb, proto_tree *tree,
                gint offset, gint tlv_len, const void *data)
{
    const char *str = (const char*)data;
    proto_item *ti = NULL;
    if (tlv_len < 2)
        return;
    ti = proto_tree_add_item(tree, tlv_vlanid, tvb, offset,
                             2, ENC_BIG_ENDIAN);
    if (str)
        proto_item_append_text(ti, " %s", str);
}

// Qos rate
static void
dissect_qos_rate(tvbuff_t *tvb, proto_tree *tree,
                 gint offset, gint tlv_len, const void *data)
{
    const char *str = (const char*)data;
    proto_item *ti = NULL;
    if (tlv_len < 2)
        return;
    ti = proto_tree_add_item(tree, tlv_qos_rate, tvb, offset,
                             2, ENC_BIG_ENDIAN);
    if (str)
        proto_item_append_text(ti, " %s", str);
}

static void
dissect_port_bitfield_single(tvbuff_t *tvb, proto_tree *tree, int p_id,
                             gint offset, gint tlv_len, const char *str)
{
    proto_item *ti = NULL;
    if (tlv_len < 1)
        return;
    ti = proto_tree_add_item(tree, p_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (str)
        proto_item_append_text(ti, " %s", str);
}

// Port bitfield
static void
dissect_port_bitfield(tvbuff_t *tvb, proto_tree *tree,
                      gint offset, gint tlv_len, const void *data,
                      guint port_group)
{
    const char *str = (const char*)data;
    if (tlv_len < 1)
        return;
    if (port_group == 0) {
        dissect_port_bitfield_single(tvb, tree, tlv_port1inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port2inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port3inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port4inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port5inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port6inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port7inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port8inbitfield, offset,
                                     tlv_len, str);
    }
    else if (port_group == 1) {
        dissect_port_bitfield_single(tvb, tree, tlv_port9inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port10inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port11inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port12inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port13inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port14inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port15inbitfield, offset,
                                     tlv_len, str);
        dissect_port_bitfield_single(tvb, tree, tlv_port16inbitfield, offset,
                                     tlv_len, str);
    }
    // Supporting only up to 16 port for now.
}

// Specialized dissectors

// IGMP Snooping status
static void
dissect_igmp_snooping_status(tvbuff_t *tvb, proto_tree *tree,
                             gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 4)
        return;
    offset += 1; // Ignore the first byte
    proto_tree_add_item(tree, tlv_enable, tvb, offset++,
                        1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, tlv_vlanid, tvb, offset,
                        2, ENC_BIG_ENDIAN);
}

// IGMP snooping static router ports
static void
dissect_igmp_snooping_static_router_ports(tvbuff_t *tvb, proto_tree *tree,
                                          gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 1)
        return;
    for (int port_group = 0; port_group < tlv_len; ++port_group)
        dissect_port_bitfield(tvb, tree, offset++, tlv_len - port_group,
                              NULL, port_group);

}

// Link status
static void
dissect_link_status(tvbuff_t *tvb, proto_tree *tree,
                    gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 2)
        return;
    proto_tree_add_item(tree, tlv_portid, tvb, offset++,
                        1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, tlv_linkstatus, tvb, offset,
                        1, ENC_BIG_ENDIAN);
}

// Ports statistics
static void
dissect_port_stats(tvbuff_t *tvb, proto_tree *tree,
                   gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 25)
        return;
    proto_tree_add_item(tree, tlv_portid, tvb, offset++,
                        1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, tlv_stat_rx_bytes, tvb, offset,
                        8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, tlv_stat_tx_bytes, tvb, offset,
                        8, ENC_BIG_ENDIAN);
    offset += 8;
    proto_tree_add_item(tree, tlv_stat_crc_err, tvb, offset,
                        8, ENC_BIG_ENDIAN);
}

// Request number of ports
static void
dissect_num_ports(tvbuff_t *tvb, proto_tree *tree,
                  gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 1)
        return;
    proto_tree_add_item(tree, tlv_numport, tvb, offset,
                        1, ENC_BIG_ENDIAN);
}

// Test cable
static void
dissect_testcable_result(tvbuff_t *tvb, proto_tree *tree,
                         gint offset, gint tlv_len, const void *data)
{
    proto_item *ti = NULL;
    const char* str = NULL;
    guint64 val = 0;

    data = data;
    if (tlv_len < 9)
        return;
    proto_tree_add_item(tree, tlv_portid, tvb, offset++,
                        1, ENC_BIG_ENDIAN);

    val = tvb_get_ntoh64(tvb, offset);
    // Should do more testing to understand how this works.
    if (val == 0x0000000000000004 || val == 0x0000000000000003)
        str = "OK";
    else if (val == 0x0000000100000000)
        str = "No cable";
    else if (val == 0x0000000200000000)
        str = "Open cable, fault at 0 meter";
    else
        str = "Unknown";
    ti = proto_tree_add_item(tree, tlv_testcableres, tvb, offset,
                             8, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, ": %s", str);
}

// Read/write mirroring configuration
static void
dissect_mirror(tvbuff_t *tvb, proto_tree *tree,
                    gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 3)
        return;
    if (tvb_get_guint8(tvb, offset) == 0) {
        proto_tree_add_item(tree, tlv_mirrordisabled, tvb, offset,
                            tlv_len, ENC_BIG_ENDIAN);
        return;
    }
    dissect_port_id(tvb, tree, offset++, tlv_len, "(destination)");
    offset += 1; // Ignore byte 1
    for (int port_group = 0; port_group < tlv_len - 2; ++port_group)
        dissect_port_bitfield(tvb, tree, offset++, tlv_len - 2 - port_group,
                              NULL, port_group);
}

// Vlan engine
static void
dissect_vlan_engine(tvbuff_t *tvb, proto_tree *tree,
                    gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 1)
        return;
    proto_tree_add_item(tree, tlv_vlan_engine, tvb, offset,
                        1, ENC_BIG_ENDIAN);
}

// Port based Vlan config
static void
dissect_portbased_vlan(tvbuff_t *tvb, proto_tree *tree,
                       gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 3)
        return;
    proto_tree_add_item(tree, tlv_vlanid, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;

    for (int port_group = 0; port_group < tlv_len - 2; ++port_group)
        dissect_port_bitfield(tvb, tree, offset++, tlv_len - 2 - port_group,
                              NULL, port_group);
}


// 802.1q Vlan config
// Default VlanId
static void
dissect_dot1q_default_vlan(tvbuff_t *tvb, proto_tree *tree,
                       gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 3)
        return;
    dissect_port_id(tvb, tree, offset++, tlv_len, data);
    proto_tree_add_item(tree, tlv_vlanid, tvb, offset,
                        2, ENC_BIG_ENDIAN);
}

// Vlan membership
static void
dissect_dot1q_vlan_membership(tvbuff_t *tvb, proto_tree *tree,
                       gint offset, gint tlv_len, const void *data)
{
    unsigned int num_groups = 0;
    data = data;
    if (tlv_len < 4)
        return;
    proto_tree_add_item(tree, tlv_vlanid, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;

     // must be multiple of 2 as we have the bitfields for vlan membership and the
     // bitfields for tagged ports.
    if ((tlv_len - 2) % 2)
        return;
    num_groups = (tlv_len - 2) / 2;
    for (unsigned int port_group = 0; port_group < num_groups; ++port_group)
        dissect_port_bitfield(tvb, tree, offset++, tlv_len - 2 - port_group,
                              "(vlan membership)", port_group);
    for (unsigned int port_group = 0; port_group < num_groups; ++port_group)
        dissect_port_bitfield(tvb, tree, offset++,
                              tlv_len - 2 - num_groups - port_group,
                              "(vlan tagging)", port_group);
}

// Qos engine
static void
dissect_qos_engine(tvbuff_t *tvb, proto_tree *tree,
                   gint offset, gint tlv_len, const void *data)
{
    data = data;
    if (tlv_len < 1)
        return;
    proto_tree_add_item(tree, tlv_qos_engine, tvb, offset,
                        1, ENC_BIG_ENDIAN);
}

// Qos priority
static void
dissect_qos_priority(tvbuff_t *tvb, proto_tree *tree,
                     gint offset, gint tlv_len, const void *data)
{
    if (tlv_len < 2)
        return;
    data = data;
    dissect_port_id(tvb, tree, offset++, tlv_len, data);
    proto_tree_add_item(tree, tlv_qos_priority, tvb, offset,
                        1, ENC_BIG_ENDIAN);
}

// Qos rate limit
static void
dissect_qos_rate_limit(tvbuff_t *tvb, proto_tree *tree,
                       gint offset, gint tlv_len, const void *data)
{
    if (tlv_len < 5)
        return;
    data = data;
    dissect_port_id(tvb, tree, offset++, tlv_len, "(destination)");
    offset += 2; // Ignore bytes 1-2
    dissect_qos_rate(tvb, tree, offset, tlv_len - 3, data);
}


// Main function for value dissection
static void
dissect_nsdp_tlv_detail(tvbuff_t *tvb, proto_tree *tree,
                        gint offset, gint tlv_len)
{
    proto_item *ti_detail = NULL;
    proto_tree *nsdp_detail_tree = NULL;

    dissect_value_detail_handler handler = NULL;
    const void *handlerData = NULL;

    guint16 tlv_tag = tvb_get_ntohs(tvb, offset);
    offset += 4;

    switch (tlv_tag) {
      case OP_DEVICE_MAC_ADDRESS:
        handler = dissect_value_mac;
        handlerData = &hf_nsdp_netdevmac;
        break;
      case OP_DEVICE_IP_ADDRESS:
        handler = dissect_value_ip;
        handlerData = &tlv_devip;
        break;
      case OP_DEVICE_IP_NETWORK_MASK:
        handler = dissect_value_ip;
        handlerData = &tlv_devnetmask;
        break;
      case OP_ROUTER_IP_ADDRESS:
        handler = dissect_value_ip;
        handlerData = &tlv_routerip;
        break;
      case OP_SPEED_LINK_STATUS:
        handler = dissect_link_status;
        break;
      case OP_PORT_TRAFFIC_STATISTICS:
        handler = dissect_port_stats;
        break;
      case OP_TEST_CABLE_REQUEST:
        handler = dissect_port_id;
        break;
      case OP_TEST_CABLE_RESULT:
        if (tlv_len == 1)
            handler = dissect_port_id;
        else
            handler = dissect_testcable_result;
        break;
      case OP_VLAN_ENGINE:
        handler = dissect_vlan_engine;
        break;
      case OP_PORT_BASED_VLAN_CONFIG:
        handler = dissect_portbased_vlan;
        break;
      case OP_DOT1Q_PORT_MEMBERSHIP:
        handler = dissect_dot1q_vlan_membership;
        break;
      case OP_DELETE_VLAN:
        handler = dissect_vlan_id;
        break;
      case OP_DOT1Q_DEFAULT_VLAN:
        if (tlv_len == 2)
            handler = dissect_vlan_id;
        else
            handler = dissect_dot1q_default_vlan;
        break;
      case OP_QOS_ENGINE:
        handler = dissect_qos_engine;
        break;
      case OP_PORT_BASED_QOS_PRIORITY:
        handler = dissect_qos_priority;
        break;
      case OP_INGRESS_BANDWIDTH_LIMIT:
        handler = dissect_qos_rate_limit;
        handlerData = "(Ingress limit)";
        break;
      case OP_EGRESS_BANDWIDTH_LIMIT:
        handler = dissect_qos_rate_limit;
        handlerData = "(Egress limit)";
        break;
      case OP_BROADCAST_FILTERING:
      case OP_DHCP_STATUS:
      case OP_BLOCK_UNKNOWN_MULTICAST_TRAFFIC:
      case OP_LOOP_DETECTION:
      case OP_IGMPV3_IP_HEADER_VALIDATION:
        handler = dissect_value_enable_disable;
        break;
      case OP_BROADCAST_BANDWIDTH:
        handler = dissect_qos_rate_limit;
        break;
      case OP_PORT_MIRRORING:
        handler = dissect_mirror;
        break;
      case OP_AVAILABLE_PORTS:
        handler = dissect_num_ports;
        break;
      case OP_IGMP_SNOOPING_STATUS:
        handler = dissect_igmp_snooping_status;
        break;
      case OP_IGMP_SNOOPING_STATIC_ROUTER_PORTS:
        handler = dissect_igmp_snooping_static_router_ports;
        break;

      case OP_DEVICE_MODEL:
      case OP_DEVICE_GIVEN_NAME:
      case OP_RESET_PORT_TRAFFIC_STATISTICS:
      case OP_ADMINISTRATION_PASSWORD:
      case OP_NEW_ADMINISTRATION_PASSWORD:
      case OP_REBOOT:
      case OP_FACTORY_RESET:
      case OP_EOM:
      case OP_DEVICE_FIRMWARE_VERSION:
      default:
        // Nothing to decode
        return;
    }

    if (!handler)
        return;

    // Detailed decoding item + subtree
    ti_detail = proto_tree_add_item( tree, nsdp_body_tlv_valdetail,
                                     tvb, offset, tlv_len, ENC_NA);
    nsdp_detail_tree = proto_item_add_subtree(ti_detail,
                                              ett_nsdp_body_tlv_detail);

    handler(tvb, nsdp_detail_tree, offset, tlv_len, handlerData);
}

static void
dissect_nsdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint msg_len;
    gint offset = 0;
    proto_item *ti = NULL;
    proto_item *ti_body = NULL;
    proto_tree *nsdp_tree = NULL;
    proto_tree *nsdp_body_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NSDP");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    if (!tree) // No details
        return;

    /* we are being asked for details */
    //Get length of NSDP message (header + payload)
    msg_len = tvb_captured_length(tvb);

    //Set base length of SNDP header
    // msg_payload_len = msg_len - NSDP_HEADER_LEN;

    ti = proto_tree_add_item(tree, proto_nsdp, tvb, 0, -1, ENC_NA);
    // NSDP tree
    nsdp_tree = proto_item_add_subtree(ti, ett_nsdp);
    // Version
    proto_tree_add_item(nsdp_tree, hf_nsdp_version, tvb, offset,
                        1, ENC_BIG_ENDIAN);
    offset += 1;
    // Opcode
    proto_tree_add_item(nsdp_tree, hf_nsdp_opcode, tvb, offset,
                        1, ENC_BIG_ENDIAN);
    offset += 1;
    // Operation result
    proto_tree_add_item(nsdp_tree, hf_nsdp_opres, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;
    // Unknown
    proto_tree_add_item(nsdp_tree, hf_nsdp_unknown1, tvb, offset,
                        4, ENC_BIG_ENDIAN);
    offset += 4;
    // Host MAC
    proto_tree_add_item(nsdp_tree, hf_nsdp_hostmac, tvb, offset,
                        6, ENC_BIG_ENDIAN);
    offset += 6;
    // Device MAC
    proto_tree_add_item(nsdp_tree, hf_nsdp_netdevmac, tvb, offset,
                        6, ENC_BIG_ENDIAN);
    offset += 6;
    // Unknown
    proto_tree_add_item(nsdp_tree, hf_nsdp_unknown2, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;
    // Sequence number
    proto_tree_add_item(nsdp_tree, hf_nsdp_seq, tvb, offset,
                        2, ENC_BIG_ENDIAN);
    offset += 2;
    // Protocol signature
    proto_tree_add_item(nsdp_tree, hf_nsdp_psig, tvb, offset,
                        4, ENC_BIG_ENDIAN);
    offset += 4;
    // Unknown
    proto_tree_add_item(nsdp_tree, hf_nsdp_unknown3, tvb, offset,
                        4, ENC_BIG_ENDIAN);
    offset += 4;
    // END HEADER

    // Message body, TLV records sequence
    ti_body = proto_tree_add_item(nsdp_tree, nsdp_body, tvb, offset,
                                  -1, ENC_NA);
    nsdp_body_tree = proto_item_add_subtree(ti_body, ett_nsdp_body);

    while (offset + 4 <= msg_len) {
        guint16 tlv_len = tvb_get_ntohs(tvb, offset + 2);
        // check if packet actually contains the specified lenth
        if (offset + 4 + tlv_len <= msg_len) {
            proto_item *ti_body_tlv = NULL;
            proto_tree *nsdp_body_tlv_tree = NULL;
            // create TLV item + subtree
            ti_body_tlv = proto_tree_add_item(nsdp_body_tree, nsdp_body_tlv,
                                              tvb, offset, 4 + tlv_len, ENC_NA);
            nsdp_body_tlv_tree = proto_item_add_subtree(ti_body_tlv,
                                                        ett_nsdp_body_tlv);

            // Tag
            proto_tree_add_item(nsdp_body_tlv_tree, nsdp_body_tlv_tag,
                                tvb, offset, 2, ENC_BIG_ENDIAN);
            // Length
            proto_tree_add_item(nsdp_body_tlv_tree, nsdp_body_tlv_len,
                                tvb, offset + 2, 2, ENC_BIG_ENDIAN);
            if (tlv_len) {
                // Value
                // Show value as hex
                proto_tree_add_item(nsdp_body_tlv_tree, nsdp_body_tlv_valhex,
                                    tvb, offset + 4, tlv_len, ENC_BIG_ENDIAN);
                // Show value as string
                proto_tree_add_item(nsdp_body_tlv_tree, nsdp_body_tlv_valstr,
                                    tvb, offset + 4, tlv_len, ENC_BIG_ENDIAN);
                // Detailed decoding
                dissect_nsdp_tlv_detail(tvb, nsdp_body_tlv_tree, offset, tlv_len);
            }
            offset += 4 + tlv_len;
        } else {
            break; // Malformed message
        }
    }
}

#if 0
static gboolean
dissect_nsdp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    data = data;
    // Version must be 1
    // Protocol signature must be NSDP
    if (tvb_get_guint8(tvb, 0) != 1
        || tvb_get_ntoh64(tvb, 0x18) != *((guint64*)"NSDP"))
        return (FALSE);
    dissect_nsdp(tvb, pinfo, tree);
    return (TRUE);
}
#endif

void
proto_register_nsdp(void)
{
    static hf_register_info hf[] = {
        { &hf_nsdp_version,
            { "Protocol version", "nsdp.version",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "NSDP protocol version.", HFILL }
        },
        { &hf_nsdp_opcode,
            { "Operation code", "nsdp.opcode",
            FT_UINT8, BASE_HEX,
            VALS(opcodenames), 0x0,
            NULL, HFILL }
        },
        { &hf_nsdp_opres,
            { "Operation result", "nsdp.opres",
            FT_UINT16, BASE_HEX,
            VALS(operationresultnames), 0x0,
            NULL, HFILL }
        },
        { &hf_nsdp_unknown1,
            { "Unknown", "nsdp.unknown1",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nsdp_hostmac,
            { "Host MAC", "nsdp.host_mac",
            FT_ETHER, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nsdp_netdevmac,
            { "Network device MAC", "nsdp.ndev_mac",
            FT_ETHER, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nsdp_unknown2,
            { "Unknown", "nsdp.unknown2",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nsdp_seq,
            { "Sequence number", "nsdp.seq",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nsdp_psig,
            { "Protocol signature", "nsdp.psig",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_nsdp_unknown3,
            { "Unknown", "nsdp.unknown3",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &nsdp_body,
            { "Message body", "nsdp.body",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            "Body of the NSDP message, sequence of TLV records.", HFILL }
        },
        { &nsdp_body_tlv,
            { "TLV record", "nsdp.body.tlv",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &nsdp_body_tlv_tag,
            { "Tag", "nsdp.body.tag",
            FT_UINT16, BASE_HEX,
            VALS(tagnames), 0x0,
            "Tag of the TLV record.", HFILL }
        },
        { &nsdp_body_tlv_len,
            { "Length", "nsdp.body.len",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Length of the TLV record.", HFILL }
        },
        { &nsdp_body_tlv_valhex,
            { "Value (hex)", "nsdp.body.val_hex",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            "Value of the TLV record.", HFILL }
        },
        { &nsdp_body_tlv_valstr,
            { "Value (str)", "nsdp.body.val_str",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            "Value of the TLV record.", HFILL }
        },
        { &nsdp_body_tlv_valdetail,
            { "Value (detail)", "nsdp.body.val_detail",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            "Value of the TLV record.", HFILL }
        },
        // For detailed value decoding
        { &tlv_enable,
            { "Enable/Disable", "nsdp.body.tlv.enable",
            FT_UINT8, BASE_HEX,
            VALS(enablenames), 0x0,
            "Feature is enabled or disabled.", HFILL }
        },
        { &tlv_vlanid,
            { "VlanId", "nsdp.body.tlv.vlanid",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            "Vlan Id.", HFILL }
        },
        { &tlv_devip,
            { "Device IP", "nsdp.body.tlv.devip",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            "Device IP address.", HFILL }
        },
        { &tlv_devnetmask,
            { "Device mask", "nsdp.body.tlv.devnetmask",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            "Device network mask.", HFILL }
        },
        { &tlv_routerip,
            { "Router IP", "nsdp.body.tlv.routerip",
            FT_IPv4, BASE_NONE,
            NULL, 0x0,
            "Router IP address.", HFILL }
        },
        { &tlv_portid,
            { "Port", "nsdp.body.tlv.portid",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Port ID.", HFILL }
        },
        { &tlv_linkstatus,
            { "Status", "nsdp.body.tlv.linkstatus",
            FT_UINT8, BASE_HEX,
            VALS(linkstatusnames), 0x0,
            "Status of the link.", HFILL }
        },
        { &tlv_stat_rx_bytes,
            { "Rx bytes", "nsdp.body.tlv.statrxbytes",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "Received bytes.", HFILL }
        },
        { &tlv_stat_tx_bytes,
            { "Tx bytes", "nsdp.body.tlv.stattxbytes",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "Transmitted bytes.", HFILL }
        },
        { &tlv_stat_crc_err,
            { "CRC errors", "nsdp.body.tlv.statcrcerr",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            "Number of CRC errors.", HFILL }
        },
        { &tlv_numport,
            { "Ports", "nsdp.body.tlv.numport",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            "Number of ports.", HFILL }
        },
        { &tlv_testcableres,
            { "Test cable", "nsdp.body.tlv.testcableres",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            "Result of test cable.", HFILL }
        },
        { &tlv_mirrordisabled,
            { "Mirroring disabled", "nsdp.body.tlv.mirrordisabled",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            "No mirroring is enabled.", HFILL }
        },
        HF_PORT_STRUCT(1),
        HF_PORT_STRUCT(2),
        HF_PORT_STRUCT(3),
        HF_PORT_STRUCT(4),
        HF_PORT_STRUCT(5),
        HF_PORT_STRUCT(6),
        HF_PORT_STRUCT(7),
        HF_PORT_STRUCT(8),
        HF_PORT_STRUCT(9),
        HF_PORT_STRUCT(10),
        HF_PORT_STRUCT(11),
        HF_PORT_STRUCT(12),
        HF_PORT_STRUCT(13),
        HF_PORT_STRUCT(14),
        HF_PORT_STRUCT(15),
        HF_PORT_STRUCT(16),
        { &tlv_vlan_engine,
            { "Vlan engine", "nsdp.body.tlv.vlanengine",
            FT_UINT8, BASE_HEX,
            VALS(vlanenginenames), 0x0,
            "Vlan engine.", HFILL }
        },
        { &tlv_qos_engine,
            { "Qos engine", "nsdp.body.tlv.qosengine",
            FT_UINT8, BASE_HEX,
            VALS(qosenginenames), 0x0,
            "Qos engine.", HFILL }
        },
        { &tlv_qos_rate,
            { "Qos rate", "nsdp.body.tlv.qosrate",
            FT_UINT16, BASE_HEX,
            VALS(qosratenames), 0x0,
            "Qos rate.", HFILL }
        },
        { &tlv_qos_priority,
            { "Qos priority", "nsdp.body.tlv.qospriority",
            FT_UINT8, BASE_HEX,
            VALS(qosprioritynames), 0x0,
            "Qos priority.", HFILL }
        },

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_nsdp,
        &ett_nsdp_body,
        &ett_nsdp_body_tlv,
        &ett_nsdp_body_tlv_detail
    };

    proto_nsdp = proto_register_protocol (
        "Netgear Switch Discovery Protocol", // name
        "NSDP", // short name
        "nsdp" // abbrev
        );

    proto_register_field_array(proto_nsdp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nsdp(void)
{
    static dissector_handle_t nsdp_handle;

    nsdp_handle = create_dissector_handle(dissect_nsdp, proto_nsdp);
    dissector_add_uint("udp.port", NSDP_PORT, nsdp_handle);
    dissector_add_uint("udp.port", 63321, nsdp_handle);
    dissector_add_uint("udp.port", 63323, nsdp_handle);
    dissector_add_uint("udp.port", 63324, nsdp_handle);


#if 0
    static gboolean nsdp_inited = FALSE;

    if (!nsdp_inited)
    {
        /* data_handle = find_dissector("data"); */

        /* Register our dissector with udp */
        heur_dissector_add("udp", dissect_nsdp_heur, "NSDP over UDP", "nsdp_udp",
                           proto_nsdp, HEURISTIC_ENABLE);

        nsdp_inited = TRUE;
    }
#endif
}

//
// Editor modelines  -  https://www.wireshark.org/tools/modelines.html
//
// Local variables:
// c-basic-offset: 4
// tab-width: 4
// indent-tabs-mode: nil
// End:
//
// vi: set shiftwidth=4 tabstop=4 expandtab:
// :indentSize=4:tabSize=4:noTabs=true:
//
