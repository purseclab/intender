/*
 * Copyright 2014-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package edu.purdue.cs.pursec.ifuzzer.criterion.api;


/**
 * Representation of a single header field selection.
 */
public interface Criterion {

    String SEPARATOR = ":";

    /**
     * Types of fields to which the selection criterion may apply.
     */
    // From page 75 of OpenFlow 1.5.0 spec
    enum Type {
        /** Switch input port. */
        IN_PORT,

        /** Switch physical input port. */
        IN_PHY_PORT,

        /** Metadata passed between tables. */
        METADATA,

        /** Ethernet destination address. */
        ETH_DST,

        /** Ethernet destination address with masking. */
        ETH_DST_MASKED,

        /** Ethernet source address. */
        ETH_SRC,

        /** Ethernet source address with masking. */
        ETH_SRC_MASKED,

        /** Ethernet frame type. */
        ETH_TYPE,

        /** VLAN id. */
        VLAN_VID,

        /** VLAN priority. */
        VLAN_PCP,

        /**
         * Inner VLAN id.
         *
         * Note: Some drivers may not support this.
         */
        INNER_VLAN_VID,

        /**
         * Inner VLAN pcp.
         *
         * Note: Some drivers may not support this.
         */
        INNER_VLAN_PCP,

        /** IP DSCP (6 bits in ToS field). */
        IP_DSCP,

        /** IP ECN (2 bits in ToS field). */
        IP_ECN,

        /** IP protocol. */
        IP_PROTO,

        /** IPv4 source address. */
        IPV4_SRC,

        /** IPv4 destination address. */
        IPV4_DST,

        /** TCP source port. */
        TCP_SRC,

        /** TCP source port with masking. */
        TCP_SRC_MASKED,

        /** TCP destination port. */
        TCP_DST,

        /** TCP destination port with masking. */
        TCP_DST_MASKED,

        /** UDP source port. */
        UDP_SRC,

        /** UDP source port with masking. */
        UDP_SRC_MASKED,

        /** UDP destination port. */
        UDP_DST,

        /** UDP destination port with masking. */
        UDP_DST_MASKED,

        /** SCTP source port. */
        SCTP_SRC,

        /** SCTP source port with masking. */
        SCTP_SRC_MASKED,

        /** SCTP destination port. */
        SCTP_DST,

        /** SCTP destination port with masking. */
        SCTP_DST_MASKED,

        /** ICMP type. */
        ICMPV4_TYPE,

        /** ICMP code. */
        ICMPV4_CODE,

        /** ARP opcode. */
        ARP_OP,

        /** ARP source IPv4 address. */
        ARP_SPA,

        /** ARP target IPv4 address. */
        ARP_TPA,

        /** ARP source hardware address. */
        ARP_SHA,

        /** ARP target hardware address. */
        ARP_THA,

        /** IPv6 source address. */
        IPV6_SRC,

        /** IPv6 destination address. */
        IPV6_DST,

        /** IPv6 Flow Label. */
        IPV6_FLABEL,

        /** ICMPv6 type. */
        ICMPV6_TYPE,

        /** ICMPv6 code. */
        ICMPV6_CODE,

        /** Target address for ND. */
        IPV6_ND_TARGET,

        /** Source link-layer for ND. */
        IPV6_ND_SLL,

        /** Target link-layer for ND. */
        IPV6_ND_TLL,

        /** MPLS label. */
        MPLS_LABEL,

        /** MPLS TC. */
        MPLS_TC,

        /**  MPLS BoS bit. */
        MPLS_BOS,

        /** PBB I-SID. */
        PBB_ISID,

        /** Logical Port Metadata. */
        TUNNEL_ID,

        /** IPv6 Extension Header pseudo-field. */
        IPV6_EXTHDR,

        /** Unassigned value: 40. */
        UNASSIGNED_40,

        /** PBB UCA header field. */
        PBB_UCA,

        /** TCP flags. */
        TCP_FLAGS,

        /** Output port from action set metadata. */
        ACTSET_OUTPUT,

        /** Packet type value. */
        PACKET_TYPE,

        //
        // NOTE: Everything below is defined elsewhere: ONOS-specific,
        // extensions, etc.
        //
        /** Optical channel signal ID (lambda). */
        OCH_SIGID,

        /** Optical channel signal type (fixed or flexible). */
        OCH_SIGTYPE,

        /** ODU (Optical channel Data Unit) signal ID. */
        ODU_SIGID,

        /** ODU (Optical channel Data Unit) signal type. */
        ODU_SIGTYPE,

        /** Protocol-independent. */
        PROTOCOL_INDEPENDENT,

        /** Extension criterion. */
        EXTENSION;

        public static Type fromInteger(int x) {
            switch (x) {
                case 0:
                    /** Switch input port. */
                    return IN_PORT;
                case 1:
                    /** Switch physical input port. */
                    return IN_PHY_PORT;
                case 2:
                    /** Metadata passed between tables. */
                    return METADATA;
                case 3:
                    /** Ethernet destination address. */
                    return ETH_DST;
                case 4:
                    /** Ethernet destination address with masking. */
                    return ETH_DST_MASKED;
                case 5:
                    /** Ethernet source address. */
                    return ETH_SRC;
                case 6:
                    /** Ethernet source address with masking. */
                    return ETH_SRC_MASKED;
                case 7:
                    /** Ethernet frame type. */
                    return ETH_TYPE;
                case 8:
                    /** VLAN id. */
                    return VLAN_VID;
                case 9:
                    /** VLAN priority. */
                    return VLAN_PCP;
                case 10:
                    /**
                     * Inner VLAN id.
                     *
                     * Note: Some drivers may not support this.
                     */
                    return INNER_VLAN_VID;
                case 11:
                    /**
                     * Inner VLAN pcp.
                     *
                     * Note: Some drivers may not support this.
                     */
                    return INNER_VLAN_PCP;
                case 12:
                    /** IP DSCP (6 bits in ToS field). */
                    return IP_DSCP;
                case 13:
                    /** IP ECN (2 bits in ToS field). */
                    return IP_ECN;
                case 14:
                    /** IP protocol. */
                    return IP_PROTO;
                case 15:
                    /** IPv4 source address. */
                    return IPV4_SRC;
                case 16:
                    /** IPv4 destination address. */
                    return IPV4_DST;
                case 17:
                    /** TCP source port. */
                    return TCP_SRC;
                case 18:
                    /** TCP source port with masking. */
                    return TCP_SRC_MASKED;
                case 19:
                    /** TCP destination port. */
                    return TCP_DST;
                case 20:
                    /** TCP destination port with masking. */
                    return TCP_DST_MASKED;
                case 21:
                    /** UDP source port. */
                    return UDP_SRC;
                case 22:
                    /** UDP source port with masking. */
                    return UDP_SRC_MASKED;
                case 23:
                    /** UDP destination port. */
                    return UDP_DST;
                case 24:
                    /** UDP destination port with masking. */
                    return UDP_DST_MASKED;
                case 25:
                    /** SCTP source port. */
                    return SCTP_SRC;
                case 26:
                    /** SCTP source port with masking. */
                    return SCTP_SRC_MASKED;
                case 27:
                    /** SCTP destination port. */
                    return SCTP_DST;
                case 28:
                    /** SCTP destination port with masking. */
                    return SCTP_DST_MASKED;
                case 29:
                    /** ICMP type. */
                    return ICMPV4_TYPE;
                case 30:
                    /** ICMP code. */
                    return ICMPV4_CODE;
                case 31:
                    /** ARP opcode. */
                    return ARP_OP;
                case 32:
                    /** ARP source IPv4 address. */
                    return ARP_SPA;
                case 33:
                    /** ARP target IPv4 address. */
                    return ARP_TPA;
                case 34:
                    /** ARP source hardware address. */
                    return ARP_SHA;
                case 35:
                    /** ARP target hardware address. */
                    return ARP_THA;
                case 36:
                    /** IPv6 source address. */
                    return IPV6_SRC;
                case 37:
                    /** IPv6 destination address. */
                    return IPV6_DST;
                case 38:
                    /** IPv6 Flow Label. */
                    return IPV6_FLABEL;
                case 39:
                    /** ICMPv6 type. */
                    return ICMPV6_TYPE;
                case 40:
                    /** ICMPv6 code. */
                    return ICMPV6_CODE;
                case 41:
                    /** Target address for ND. */
                    return IPV6_ND_TARGET;
                case 42:
                    /** Source link-layer for ND. */
                    return IPV6_ND_SLL;
                case 43:
                    /** Target link-layer for ND. */
                    return IPV6_ND_TLL;
                case 44:
                    /** MPLS label. */
                    return MPLS_LABEL;
                case 45:
                    /** MPLS TC. */
                    return MPLS_TC;
                case 46:
                    /**  MPLS BoS bit. */
                    return MPLS_BOS;
                case 47:
                    /** PBB I-SID. */
                    return PBB_ISID;
                case 48:
                    /** Logical Port Metadata. */
                    return TUNNEL_ID;
                case 49:
                    /** IPv6 Extension Header pseudo-field. */
                    return IPV6_EXTHDR;
                case 50:
                    /** Unassigned value: 40. */
                    return UNASSIGNED_40;
                case 51:
                    /** PBB UCA header field. */
                    return PBB_UCA;
                case 52:
                    /** TCP flags. */
                    return TCP_FLAGS;
                case 53:
                    /** Output port from action set metadata. */
                    return ACTSET_OUTPUT;
                case 54:
                    /** Packet type value. */
                    return PACKET_TYPE;
                case 55:
                    //
                    // NOTE: Everything below is defined elsewhere: ONOS-specific,
                    // extensions, etc.
                    //
                    /** Optical channel signal ID (lambda). */
                    return OCH_SIGID;
                case 56:
                    /** Optical channel signal type (fixed or flexible). */
                    return OCH_SIGTYPE;
                case 57:
                    /** ODU (Optical channel Data Unit) signal ID. */
                    return ODU_SIGID;
                case 58:
                    /** ODU (Optical channel Data Unit) signal type. */
                    return ODU_SIGTYPE;
                case 59:
                    /** Protocol-independent. */
                    return PROTOCOL_INDEPENDENT;
                case 60:
                    /** Extension criterion. */
                    return EXTENSION;
            }
            return null;
        }
    }

    /**
     * Returns the type of criterion.
     *
     * @return type of criterion
     */
    Type type();

    /**
     * Bit definitions for IPv6 Extension Header pseudo-field.
     * From page 79 of OpenFlow 1.5.0 spec.
     */
    enum IPv6ExthdrFlags {
        /** "No next header" encountered. */
        NONEXT((short) (1 << 0)),
        /** Encrypted Sec Payload header present. */
        ESP((short) (1 << 1)),
        /** Authentication header present. */
        AUTH((short) (1 << 2)),
        /** 1 or 2 dest headers present. */
        DEST((short) (1 << 3)),
        /** Fragment header present. */
        FRAG((short) (1 << 4)),
        /** Router header present. */
        ROUTER((short) (1 << 5)),
        /** Hop-by-hop header present. */
        HOP((short) (1 << 6)),
        /** Unexpected repeats encountered. */
        UNREP((short) (1 << 7)),
        /** Unexpected sequencing encountered. */
        UNSEQ((short) (1 << 8));

        private short value;

        IPv6ExthdrFlags(short value) {
            this.value = value;
        }

        /**
         * Gets the value as an integer.
         *
         * @return the value as an integer
         */
        public short getValue() {
            return this.value;
        }
    }

    enum TcpFlags {

        /** ECN-nonce concealment protection. */
        NS((short) (1 << 0)),
        /** Congestion Window Reduced. */
        CWR((short) (1 << 1)),
        /** ECN-Echo. **/
        ECE((short) (1 << 2)),
        /** Urgent pointer field is significant. */
        URG((short) (1 << 3)),
        /** Acknowledgment field is significant. */
        ACK((short) (1 << 4)),
        /** Push the buffered data to the receiving application. */
        PSH((short) (1 << 5)),
        /** Reset the connection. */
        RST((short) (1 << 6)),
        /** Synchronize sequence numbers. */
        SYN((short) (1 << 7)),
        /** No more data from sender. */
        FIN((short) (1 << 8));

        private short value;

        TcpFlags(short value) {
            this.value = value;
        }

        /**
         * Gets the value as an integer.
         *
         * @return the value as an integer
         */
        public short getValue() {
            return this.value;
        }
    }
}
