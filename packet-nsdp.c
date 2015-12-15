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

void proto_register_nsdp(void);
void proto_reg_handoff_nsdp(void);

static int proto_nsdp = -1;
static gint ett_nsdp = -1;
static gint ett_nsdp_body = -1;
static gint ett_nsdp_body_tlv = -1;

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

static const value_string opcodenames[] = {
    { 1, "Read request" },
    { 2, "Read response" },
    { 3, "Write request" },
    { 4, "Write response" },
    { 0, NULL }
};

static const value_string tagnames[] = {
    // General info
    { 0x1, "Device model" },
    { 0x3, "Device given name" },

    // Network info
    { 0x4, "Device MAC address" },
    { 0x6, "Device IP address" },
    { 0x7, "Device IP network mask" },
    { 0x8, "Router IP address (gateway)" },

    // Admin
    { 0x9, "New administration password" },
    { 0xa, "Administration password" },
    { 0xb, "DHCP Status" },
    { 0xd, "Device firmware version" },
    { 0x13, "Reboot" },
    { 0x400, "Factory Reset" },

    // Statistics/status
    { 0xc00, "Speed/Link status" },
    { 0x1000, "Port traffic statistics" },
    { 0x1400, "Reset port traffic statistics" },
    { 0x1800, "Test cable request" },
    { 0x1c00, "Test cable result" },


    // Vlan configuration
    { 0x2000, "VLAN Engine" }, // basic/advanced port based, basic/advanced 802.1q
    // 2 bytes = vlanId, 1-X bytes port bitfield
    { 0x2400, "Port based VLAN config" },
    { 0x2800, "802.1q Port membership" },
    { 0x2c00, "Delete VLAN" },
    { 0x3000, "802.1q default vlan (PVID)" },

    // Qos
    { 0x3400, "QOS engine" }, // 1 = port based; 2 = 802.1p
    // 1 byte port; 1 byte priority (1 = high, 2 = medium, 3 = normal, 4 = low)
    { 0x3800, "Port based QOS - priority" },
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
    { 0x4c00, "Ingress bandwidth limit" },
    { 0x5000, "Egress bandwidth limit" }, // same
    { 0x5800, "Broadcast bandwidth (storm control)" }, // same

    // Mirroring
    // 1 byte = destination port, 2 bytes source port bitfield
    { 0x5c00, "Port mirroring" },
    { 0x6000, "Available ports" },

    // Multicast
    { 0x6800, "IGMP Snooping status" }, // 1 byte == 00, 1 byte = 0/1, 2 bytes vlanId
    { 0x6c00, "Block unknown multicast traffic" }, // 1 byte = 0/1
    { 0x7000, "IGMPv3 IP header validation" }, // 1 byte = 0/1
    { 0x8000, "IGMP Snooping static router ports" }, // 2 bytes: port bitfield

    { 0x9000, "Loop detection" }, // 1 byte = 0/1

    { 0xffff, "End Of Message" },
    { 0, NULL }
};


static void
dissect_nsdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NSDP");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) { /* we are being asked for details */
        //Get length of NSDP message (header + payload)
        gint msg_len = tvb_captured_length(tvb);

        //Set base length of SNDP header
        // msg_payload_len = msg_len - NSDP_HEADER_LEN;

        gint offset = 0;
        proto_item *ti = NULL;
        proto_item *ti_body = NULL;
        proto_item *ti_body_tlv = NULL;
        proto_tree * nsdp_tree = NULL;
        proto_tree * nsdp_body_tree = NULL;
        proto_tree * nsdp_body_tlv_tree = NULL;
        ti = proto_tree_add_item(tree, proto_nsdp, tvb, 0, -1, ENC_NA);
        nsdp_tree = proto_item_add_subtree(ti, ett_nsdp);
        proto_tree_add_item(nsdp_tree, hf_nsdp_version, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(nsdp_tree, hf_nsdp_opcode, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(nsdp_tree, hf_nsdp_opres, tvb, offset,
                            2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(nsdp_tree, hf_nsdp_unknown1, tvb, offset,
                            4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(nsdp_tree, hf_nsdp_hostmac, tvb, offset,
                            6, ENC_BIG_ENDIAN);
        offset += 6;
        proto_tree_add_item(nsdp_tree, hf_nsdp_netdevmac, tvb, offset,
                            6, ENC_BIG_ENDIAN);
        offset += 6;
        proto_tree_add_item(nsdp_tree, hf_nsdp_unknown2, tvb, offset,
                            2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(nsdp_tree, hf_nsdp_seq, tvb, offset,
                            2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(nsdp_tree, hf_nsdp_psig, tvb, offset,
                            4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(nsdp_tree, hf_nsdp_unknown3, tvb, offset,
                            4, ENC_BIG_ENDIAN);
        offset += 4;
        // END HEADER

        // Message body, TLV records sequence
        ti_body = proto_tree_add_item(nsdp_tree, nsdp_body, tvb, offset,
                                      -1, ENC_NA);
        nsdp_body_tree = proto_item_add_subtree(ti_body, ett_nsdp_body);

        while (offset + 4 <= msg_len) {
            /* guint16 tlv_tag = tvb_get_ntohs(tvb, offset); */
            guint16 tlv_len = tvb_get_ntohs(tvb, offset + 2);
            if (offset + 4 + tlv_len <= msg_len) {
                ti_body_tlv = proto_tree_add_item(nsdp_body_tree, nsdp_body_tlv,
                                                  tvb, offset, 4 + tlv_len, ENC_NA);
                nsdp_body_tlv_tree = proto_item_add_subtree(ti_body_tlv,
                                                            ett_nsdp_body_tlv);

                proto_tree_add_item(nsdp_body_tlv_tree, nsdp_body_tlv_tag,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(nsdp_body_tlv_tree, nsdp_body_tlv_len,
                                    tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                if (tlv_len) {
                    proto_tree_add_item(nsdp_body_tlv_tree, nsdp_body_tlv_valhex,
                                        tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    proto_tree_add_item(nsdp_body_tlv_tree, nsdp_body_tlv_valstr,
                                        tvb, offset, tlv_len, ENC_BIG_ENDIAN);
                    offset += tlv_len;
                }
            } else {
                break; // Malformed message
            }
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
            NULL, 0x0,
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

    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_nsdp,
        &ett_nsdp_body,
        &ett_nsdp_body_tlv
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
