package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion.Type;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import org.projectfloodlight.openflow.types.IpProtocol;

import java.util.EnumMap;
import java.util.Random;

import static com.google.common.base.Preconditions.checkNotNull;

public class SelectorGenerator {
    private static final Random rand = new Random();
    private final EnumMap<Type, CriterionGenerator> generateMap;
    private final EnumMap<Type, CriterionGenerator> prerequisiteMap;
    private final EnumMap<Type, CriterionJsonFormatter> formatMap;
    private final int criteriaMaxNum;

    static final String TYPE = "type";

    static final String ETH_TYPE = "ethType";
    static final String MAC = "mac";
    static final String MAC_MASK = "macMask";
    static final String PORT = "port";
    static final String METADATA = "metadata";

    static final String VLAN_ID = "vlanId";
    static final String INNER_VLAN_ID = "innerVlanId";
    static final String INNER_PRIORITY = "innerPriority";
    static final String PRIORITY = "priority";
    static final String IP_DSCP = "ipDscp";
    static final String IP_ECN = "ipEcn";
    static final String PROTOCOL = "protocol";
    static final String IP = "ip";
    static final String TCP_PORT = "tcpPort";
    static final String TCP_MASK = "tcpMask";
    static final String UDP_PORT = "udpPort";
    static final String UDP_MASK = "udpMask";
    static final String SCTP_PORT = "sctpPort";
    static final String SCTP_MASK = "sctpMask";
    static final String ICMP_TYPE = "icmpType";
    static final String ICMP_CODE = "icmpCode";
    static final String FLOW_LABEL = "flowLabel";
    static final String ICMPV6_TYPE = "icmpv6Type";
    static final String ICMPV6_CODE = "icmpv6Code";
    static final String TARGET_ADDRESS = "targetAddress";
    static final String LABEL = "label";
    static final String BOS = "bos";
    static final String EXT_HDR_FLAGS = "exthdrFlags";
    static final String LAMBDA = "lambda";
    static final String GRID_TYPE = "gridType";
    static final String CHANNEL_SPACING = "channelSpacing";
    static final String SPACING_MULIPLIER = "spacingMultiplier";
    static final String SLOT_GRANULARITY = "slotGranularity";
    static final String OCH_SIGNAL_ID = "ochSignalId";
    static final String TUNNEL_ID = "tunnelId";
    static final String OCH_SIGNAL_TYPE = "ochSignalType";
    static final String ODU_SIGNAL_ID = "oduSignalId";
    static final String TRIBUTARY_PORT_NUMBER = "tributaryPortNumber";
    static final String TRIBUTARY_SLOT_LEN = "tributarySlotLen";
    static final String TRIBUTARY_SLOT_BITMAP = "tributarySlotBitmap";
    static final String ODU_SIGNAL_TYPE = "oduSignalType";
    static final String PI_MATCHES = "matches";
    static final String PI_MATCH_FIELD_ID = "field";
    static final String PI_MATCH_TYPE = "match";
    static final String PI_MATCH_VALUE = "value";
    static final String PI_MATCH_PREFIX = "prefixLength";
    static final String PI_MATCH_MASK = "mask";
    static final String PI_MATCH_HIGH_VALUE = "highValue";
    static final String PI_MATCH_LOW_VALUE = "lowValue";
    static final String EXTENSION = "extension";

    public SelectorGenerator() {
        formatMap = new EnumMap<>(Criterion.Type.class);
        generateMap = new EnumMap<>(Criterion.Type.class);
        prerequisiteMap = new EnumMap<>(Criterion.Type.class);

        formatMap.put(Criterion.Type.IP_PROTO, new FormatIpProto());
        generateMap.put(Criterion.Type.IP_PROTO, new RandomSelectorIpProto());
        prerequisiteMap.put(Criterion.Type.IP_PROTO, new PreRequisiteIp());

        /* Generator/Formatter implemented */
//        generateMap.put(Criterion.Type.IN_PORT, new RandomSelectorInPort());
//        generateMap.put(Criterion.Type.IN_PHY_PORT, new RandomSelectorInPort());
//        generateMap.put(Criterion.Type.ETH_DST, new RandomSelectorEth());
//        generateMap.put(Criterion.Type.ETH_DST_MASKED, new RandomSelectorEthMasked());
//        generateMap.put(Criterion.Type.ETH_SRC, new RandomSelectorEth());
//        generateMap.put(Criterion.Type.ETH_TYPE, new RandomSelectorEthType());
//        generateMap.put(Criterion.Type.VLAN_VID, new RandomSelectorVlanVid());
//        generateMap.put(Criterion.Type.VLAN_PCP, new RandomSelectorVlanPcp());
//        generateMap.put(Criterion.Type.INNER_VLAN_VID, new RandomSelectorInnerVlanVid());
//        generateMap.put(Criterion.Type.INNER_VLAN_PCP, new RandomSelectorInnerVlanPcp());
//        generateMap.put(Criterion.Type.IP_DSCP, new RandomSelectorIpDscp());
//        generateMap.put(Criterion.Type.IP_ECN, new RandomSelectorIpEcn());
//        generateMap.put(Criterion.Type.IPV4_SRC, new RandomSelectorIp());
//        generateMap.put(Criterion.Type.IPV4_DST, new RandomSelectorIp());
//        generateMap.put(Criterion.Type.TCP_SRC, new RandomSelectorTcp());
//        generateMap.put(Criterion.Type.TCP_SRC_MASKED, new RandomSelectorTcpMask());
//        generateMap.put(Criterion.Type.TCP_DST, new RandomSelectorTcp());
//        generateMap.put(Criterion.Type.TCP_DST_MASKED, new RandomSelectorTcpMask());
//        generateMap.put(Criterion.Type.UDP_SRC, new RandomSelectorUdp());
//        generateMap.put(Criterion.Type.UDP_SRC_MASKED, new RandomSelectorUdpMask());
//        generateMap.put(Criterion.Type.UDP_DST, new RandomSelectorUdp());
//        generateMap.put(Criterion.Type.UDP_DST_MASKED, new RandomSelectorUdpMask());
//        generateMap.put(Criterion.Type.SCTP_SRC, new RandomSelectorSctp());
//        generateMap.put(Criterion.Type.SCTP_SRC_MASKED, new RandomSelectorSctpMask());
//        generateMap.put(Criterion.Type.SCTP_DST, new RandomSelectorSctp());
//        generateMap.put(Criterion.Type.SCTP_DST_MASKED, new RandomSelectorSctpMask());
//        generateMap.put(Criterion.Type.ICMPV4_TYPE, new RandomSelectorIcmpV4Type());
//        generateMap.put(Criterion.Type.ICMPV4_CODE, new RandomSelectorIcmpV4Code());

//        formatMap.put(Criterion.Type.IN_PORT, new FormatInPort());
//        formatMap.put(Criterion.Type.IN_PHY_PORT, new FormatInPort());
//        formatMap.put(Criterion.Type.ETH_DST, new FormatEth());
//        formatMap.put(Criterion.Type.ETH_DST_MASKED, new FormatEthMasked());
//        formatMap.put(Criterion.Type.ETH_SRC, new FormatEth());
//        formatMap.put(Criterion.Type.ETH_TYPE, new FormatEthType());
//        formatMap.put(Criterion.Type.VLAN_VID, new FormatVlanVid());
//        formatMap.put(Criterion.Type.VLAN_PCP, new FormatVlanPcp());
//        formatMap.put(Criterion.Type.INNER_VLAN_VID, new FormatInnerVlanVid());
//        formatMap.put(Criterion.Type.INNER_VLAN_PCP, new FormatInnerVlanPcp());
//        formatMap.put(Criterion.Type.IP_DSCP, new FormatIpDscp());
//        formatMap.put(Criterion.Type.IP_ECN, new FormatIpEcn());
//        formatMap.put(Criterion.Type.IPV4_SRC, new FormatIp());
//        formatMap.put(Criterion.Type.IPV4_DST, new FormatIp());
//        formatMap.put(Criterion.Type.TCP_SRC, new FormatTcp());
//        formatMap.put(Criterion.Type.TCP_SRC_MASKED, new FormatTcpMask());
//        formatMap.put(Criterion.Type.TCP_DST, new FormatTcp());
//        formatMap.put(Criterion.Type.TCP_DST_MASKED, new FormatTcpMask());
//        formatMap.put(Criterion.Type.UDP_SRC, new FormatUdp());
//        formatMap.put(Criterion.Type.UDP_SRC_MASKED, new FormatUdpMask());
//        formatMap.put(Criterion.Type.UDP_DST, new FormatUdp());
//        formatMap.put(Criterion.Type.UDP_DST_MASKED, new FormatUdpMask());
//        formatMap.put(Criterion.Type.SCTP_SRC, new FormatSctp());
//        formatMap.put(Criterion.Type.SCTP_SRC_MASKED, new FormatSctpMask());
//        formatMap.put(Criterion.Type.SCTP_DST, new FormatSctp());
//        formatMap.put(Criterion.Type.SCTP_DST_MASKED, new FormatSctpMask());
//        formatMap.put(Criterion.Type.ICMPV4_TYPE, new FormatIcmpV4Type());
//        formatMap.put(Criterion.Type.ICMPV4_CODE, new FormatIcmpV4Code());


        /* Generator/Formatter unimplemented */
//        generateMap.put(Criterion.Type.METADATA, new RandomSelectorMetadata());
//        generateMap.put(Criterion.Type.IPV6_SRC, new RandomSelectorIp());
//        generateMap.put(Criterion.Type.IPV6_DST, new RandomSelectorIp());
//        generateMap.put(Criterion.Type.IPV6_FLABEL, new RandomSelectorIpV6FLabel());
//        generateMap.put(Criterion.Type.ICMPV6_TYPE, new RandomSelectorIcmpV6Type());
//        generateMap.put(Criterion.Type.ICMPV6_CODE, new RandomSelectorIcmpV6Code());
//        generateMap.put(Criterion.Type.IPV6_ND_TARGET, new RandomSelectorV6NDTarget());
//        generateMap.put(Criterion.Type.IPV6_ND_SLL, new RandomSelectorV6NDTll());
//        generateMap.put(Criterion.Type.IPV6_ND_TLL, new RandomSelectorV6NDTll());
//        generateMap.put(Criterion.Type.MPLS_LABEL, new RandomSelectorMplsLabel());
//        generateMap.put(Criterion.Type.MPLS_BOS, new RandomSelectorMplsBos());
//        generateMap.put(Criterion.Type.IPV6_EXTHDR, new RandomSelectorIpV6Exthdr());
//        generateMap.put(Criterion.Type.OCH_SIGID, new RandomSelectorOchSigId());
//        generateMap.put(Criterion.Type.OCH_SIGTYPE, new RandomSelectorOchSigType());
//        generateMap.put(Criterion.Type.TUNNEL_ID, new RandomSelectorTunnelId());
//        generateMap.put(Criterion.Type.ODU_SIGID, new RandomSelectorOduSignalId());
//        generateMap.put(Criterion.Type.ODU_SIGTYPE, new RandomSelectorOduSignalType());
//        generateMap.put(Criterion.Type.PROTOCOL_INDEPENDENT, new RandomSelectorProtocolIndependent());
//        generateMap.put(Criterion.Type.EXTENSION, new RandomSelectorExtension());

        /* Currently unimplemented in ONOS */
//        generateMap.put(Criterion.Type.ARP_OP, new FormatUnknown);
//        generateMap.put(Criterion.Type.ARP_SPA, new FormatUnknown());
//        generateMap.put(Criterion.Type.ARP_TPA, new FormatUnknown());
//        generateMap.put(Criterion.Type.ARP_SHA, new FormatUnknown());
//        generateMap.put(Criterion.Type.ARP_THA, new FormatUnknown());
//        generateMap.put(Criterion.Type.MPLS_TC, new FormatUnknown());
//        generateMap.put(Criterion.Type.PBB_ISID, new FormatUnknown());
//        generateMap.put(Criterion.Type.UNASSIGNED_40, new FormatUnknown());
//        generateMap.put(Criterion.Type.PBB_UCA, new FormatUnknown());
//        generateMap.put(Criterion.Type.TCP_FLAGS, new FormatUnknown());
//        generateMap.put(Criterion.Type.ACTSET_OUTPUT, new FormatUnknown());
//        generateMap.put(Criterion.Type.PACKET_TYPE, new FormatUnknown());
//        generateMap.put(Criterion.Type.ETH_SRC_MASKED, new FormatUnknown());
//        generateMap.put(Criterion.Type.TCP_SRC_MASKED, new FormatUnknown());
//        generateMap.put(Criterion.Type.TCP_DST_MASKED, new FormatUnknown());
//        generateMap.put(Criterion.Type.UDP_SRC_MASKED, new FormatUnknown());
//        generateMap.put(Criterion.Type.UDP_DST_MASKED, new FormatUnknown());
//        generateMap.put(Criterion.Type.SCTP_SRC_MASKED, new FormatUnknown());
//        generateMap.put(Criterion.Type.SCTP_DST_MASKED, new FormatUnknown());

        criteriaMaxNum = generateMap.size();
    }

    public JsonObject randomSelector(int criteriaNum) {
        if (criteriaNum > criteriaMaxNum)
            return null;

        JsonObject selectorJson = new JsonObject();
        JsonArray criteriaJson = new JsonArray();

        boolean []criteriaBitmap = new boolean[61];
        for (int i = 0; i < 61; i++)
            criteriaBitmap[i] = false;

        for (int i = 0; i < criteriaNum; i++) {
            int idx = rand.nextInt(61);
            if (criteriaBitmap[idx]) {
                i --;
                continue;
            }

            // get random type
            Type type = Type.fromInteger(idx);

            // get generator
            CriterionGenerator generator = generateMap.get(type);
            if (generator == null) {
                i --;
                continue;
            }

            // generate random criterion
            generator.randomCriterion(type, criteriaJson);

            criteriaBitmap[idx] = true;
        }

        for (int i = 0; i < 61; i++) {
            if (!criteriaBitmap[i])
                continue;

            Type type = Type.fromInteger(i);
            CriterionGenerator preReqGenerator = prerequisiteMap.get(type);
            if (preReqGenerator == null)
                continue;

            preReqGenerator.randomCriterion(type, criteriaJson);
        }

        selectorJson.add("criteria", criteriaJson);

        return selectorJson;
    }

    public void encodeCriterion(JsonObject jsonObject, Criterion criterion) {
        CriterionJsonFormatter formatter = formatMap.get(criterion.type());
        if (formatter != null) {
            jsonObject.addProperty(SelectorGenerator.TYPE, criterion.type().toString());
            formatter.encodeCriterion(jsonObject, criterion);
        }
    }

    private interface CriterionGenerator {
        void randomCriterion(Type type, JsonArray criteriaJson);
    }

    private interface CriterionJsonFormatter {
        void encodeCriterion(JsonObject jsonObject, Criterion criterion);
    }

    /** IN PORT **/
    private static class RandomSelectorInPort implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.PORT, FuzzUtil.randomPortNo(rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatInPort implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject jsonObject, Criterion criterion) {
            final PortCriterion portCriterion = (PortCriterion) criterion;
            jsonObject.addProperty(SelectorGenerator.PORT, portCriterion.portNo());
        }
    }

//    private static class RandomSelectorMetadata implements CriterionGenerator {
//        @Override
//        public void randomCriterion(JsonObject jsonObject) {
//            jsonObject.addProperty(SelectorGenerator.METADATA, rand.nextLong());
//        }
//    }

    /** ETHERNET **/
    private static class RandomSelectorEth implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.MAC, FuzzUtil.randomMacAddress(false, rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatEth implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final EthCriterion ethCriterion = (EthCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.MAC, ethCriterion.mac().toString());
        }
    }

    /** ETHERNET MASK **/
    private static class RandomSelectorEthMasked implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.MAC, FuzzUtil.randomMacAddress(false, rand));
            criterionJson.addProperty(SelectorGenerator.MAC_MASK, FuzzUtil.randomMacAddress(false, rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatEthMasked implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final EthCriterion ethCriterion = (EthCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.MAC, ethCriterion.mac().toString());
            criterionJson.addProperty(SelectorGenerator.MAC_MASK, ethCriterion.mask().toString());
        }
    }

    /** ETHERNET TYPE **/
    private static class RandomSelectorEthType implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.ETH_TYPE, "0x"
                    + Integer.toHexString(FuzzUtil.randomEthType(true, rand) & 0xffff));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatEthType implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final EthTypeCriterion ethTypeCriterion = (EthTypeCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.ETH_TYPE, "0x"
                    + Integer.toHexString(ethTypeCriterion.ethType().getValue() & 0xffff));
        }
    }

    /** VLAN ID **/
    private static class RandomSelectorVlanVid implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            try {
                JsonObject criterionJson = new JsonObject();
                criterionJson.addProperty(TYPE, type.toString());
                criterionJson.addProperty(SelectorGenerator.VLAN_ID, Integer.parseInt(FuzzUtil.randomVlanId(false, rand)));
                criteriaJson.add(criterionJson);
            } catch (NumberFormatException e) {
                e.printStackTrace();
            }
        }
    }

    private static class FormatVlanVid implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            try {
                final VlanIdCriterion vlanIdCriterion = (VlanIdCriterion) criterion;
                criterionJson.addProperty(SelectorGenerator.VLAN_ID, vlanIdCriterion.vlanId());
            } catch (NumberFormatException e) {
                e.printStackTrace();
            }
        }
    }

    /** VLAN PCP **/
    private static class RandomSelectorVlanPcp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.PRIORITY, rand.nextInt(8));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatVlanPcp implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final VlanPcpCriterion vlanPcpCriterion = (VlanPcpCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.PRIORITY, vlanPcpCriterion.vlanPcp());
        }
    }

    /** INNER VLAN ID **/
    private static class RandomSelectorInnerVlanVid implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.INNER_VLAN_ID, Integer.parseInt(FuzzUtil.randomVlanId(false, rand)));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatInnerVlanVid implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final VlanIdCriterion vlanIdCriterion = (VlanIdCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.INNER_VLAN_ID, vlanIdCriterion.vlanId());
        }
    }

    /** INNER VLAN PCP **/
    private static class RandomSelectorInnerVlanPcp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.INNER_PRIORITY, rand.nextInt(8));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatInnerVlanPcp implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final VlanPcpCriterion vlanPcpCriterion = (VlanPcpCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.INNER_PRIORITY, vlanPcpCriterion.vlanPcp());
        }
    }

    /** IP DSCP **/
    private static class RandomSelectorIpDscp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.IP_DSCP, rand.nextInt(0x40));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatIpDscp implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final IPDscpCriterion ipDscpCriterion = (IPDscpCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.IP_DSCP, ipDscpCriterion.ipDscp());
        }
    }

    /** IP ECN **/
    private static class RandomSelectorIpEcn implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.IP_ECN, rand.nextInt(4));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatIpEcn implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final IPEcnCriterion ipEcnCriterion = (IPEcnCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.IP_ECN, ipEcnCriterion.ipEcn());
        }
    }

    /** IP PROTO **/
    private static class PreRequisiteIp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {

            // ipProto requires ethType as 0x800 / 0x86dd
            for (JsonElement criterionJsonElem : criteriaJson) {
                if (!criterionJsonElem.isJsonObject())
                    continue;

                JsonObject criterionJson = criterionJsonElem.getAsJsonObject();
                if (!criterionJson.has(SelectorGenerator.TYPE) ||
                        !criterionJson.get(SelectorGenerator.TYPE).getAsString().equals(Type.ETH_TYPE.toString()))
                    continue;

                // FOUND
                String ethTypeStr = criterionJson.get(SelectorGenerator.ETH_TYPE).getAsString();
                int ethType;
                if (ethTypeStr.startsWith("0x"))
                    ethType = Integer.parseInt(ethTypeStr.substring(2), 16);
                else
                    ethType = Integer.parseInt(ethTypeStr);

                if (ethType != 0x800 && ethType != 0x86dd) {
                    // TODO: check IPv6?
                    criterionJson.addProperty(SelectorGenerator.ETH_TYPE, "0x800");
                }

                return;
            }

            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, Type.ETH_TYPE.toString());
            criterionJson.addProperty(SelectorGenerator.ETH_TYPE, "0x800");
            criteriaJson.add(criterionJson);
        }
    }

    private static class RandomSelectorIpProto implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.PROTOCOL, FuzzUtil.randomIpProto(true, rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatIpProto implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final IPProtoCriterion ipProtoCriterion = (IPProtoCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.PROTOCOL, ipProtoCriterion.protocol());
        }
    }

    /** IP **/
    private static class PreRequisiteIpv4 implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {

            // ipProto requires ethType as 0x800
            for (JsonElement criterionJsonElem : criteriaJson) {
                if (!criterionJsonElem.isJsonObject())
                    continue;

                JsonObject criterionJson = criterionJsonElem.getAsJsonObject();
                if (!criterionJson.has(SelectorGenerator.TYPE) ||
                        !criterionJson.get(SelectorGenerator.TYPE).getAsString().equals(Type.ETH_TYPE.toString()))
                    continue;

                // set 0x800 always
                criterionJson.addProperty(SelectorGenerator.ETH_TYPE, "0x800");

                return;
            }

            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, Type.ETH_TYPE.toString());
            criterionJson.addProperty(SelectorGenerator.ETH_TYPE, "0x800");
            criteriaJson.add(criterionJson);
        }
    }

    private static class RandomSelectorIp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.IP, FuzzUtil.randomIp(rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatIp implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final IPCriterion ipCriterion = (IPCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.IP, ipCriterion.ip().toString());
        }
    }

    /** TCP **/
    private static class PreRequisiteTcp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {

            // generate IpProto-prerequisite (0x800 or 0x86dd) First
            PreRequisiteIp generator = new PreRequisiteIp();
            generator.randomCriterion(type, criteriaJson);

            // tcp requires ipProto as 6
            for (JsonElement criterionJsonElem : criteriaJson) {
                if (!criterionJsonElem.isJsonObject())
                    continue;

                JsonObject criterionJson = criterionJsonElem.getAsJsonObject();
                if (!criterionJson.has(SelectorGenerator.TYPE) ||
                        !criterionJson.get(SelectorGenerator.TYPE).getAsString().equals(Type.IP_PROTO.toString()))
                    continue;

                // set 6 always
                criterionJson.addProperty(SelectorGenerator.PROTOCOL, IpProtocol.TCP.getIpProtocolNumber());

                return;
            }

            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, Type.IP_PROTO.toString());
            criterionJson.addProperty(SelectorGenerator.PROTOCOL, IpProtocol.TCP.getIpProtocolNumber());
            criteriaJson.add(criterionJson);
        }
    }

    private static class RandomSelectorTcp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.TCP_PORT, FuzzUtil.randomTpPort(rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatTcp implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final TpCriterion tpCriterion = (TpCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.TCP_PORT, tpCriterion.port());
        }
    }

    /** TCP MASK **/
    private static class RandomSelectorTcpMask implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.TCP_PORT, FuzzUtil.randomTpPort(rand));
            criterionJson.addProperty(SelectorGenerator.TCP_MASK, FuzzUtil.randomTpPort(rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatTcpMask implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final TpCriterion tpCriterion = (TpCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.TCP_PORT, tpCriterion.port());
            criterionJson.addProperty(SelectorGenerator.TCP_MASK, tpCriterion.mask());
        }
    }

    /** UDP **/
    private static class PreRequisiteUdp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {

            // generate IpProto-prerequisite (0x800 or 0x86dd) First
            PreRequisiteIp generator = new PreRequisiteIp();
            generator.randomCriterion(type, criteriaJson);

            // udp requires ipProto as 17
            for (JsonElement criterionJsonElem : criteriaJson) {
                if (!criterionJsonElem.isJsonObject())
                    continue;

                JsonObject criterionJson = criterionJsonElem.getAsJsonObject();
                if (!criterionJson.has(SelectorGenerator.TYPE) ||
                        !criterionJson.get(SelectorGenerator.TYPE).getAsString().equals(Type.IP_PROTO.toString()))
                    continue;

                // set 17 always
                criterionJson.addProperty(SelectorGenerator.PROTOCOL, IpProtocol.UDP.getIpProtocolNumber());

                return;
            }

            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, Type.IP_PROTO.toString());
            criterionJson.addProperty(SelectorGenerator.PROTOCOL, IpProtocol.UDP.getIpProtocolNumber());
            criteriaJson.add(criterionJson);
        }
    }

    private static class RandomSelectorUdp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.UDP_PORT, FuzzUtil.randomTpPort(rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatUdp implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final TpCriterion tpCriterion = (TpCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.UDP_PORT, tpCriterion.port());
        }
    }

    /** UDP MASK **/
    private static class RandomSelectorUdpMask implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.UDP_PORT, FuzzUtil.randomTpPort(rand));
            criterionJson.addProperty(SelectorGenerator.UDP_MASK, FuzzUtil.randomTpPort(rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatUdpMask implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final TpCriterion tpCriterion = (TpCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.UDP_PORT, tpCriterion.port());
            criterionJson.addProperty(SelectorGenerator.UDP_MASK, tpCriterion.mask());
        }
    }

    /** SCTP **/
    private static class PreRequisiteSctp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {

            // generate IpProto-prerequisite (0x800 or 0x86dd) First
            PreRequisiteIp generator = new PreRequisiteIp();
            generator.randomCriterion(type, criteriaJson);

            // sctp requires ipProto as 0x84
            for (JsonElement criterionJsonElem : criteriaJson) {
                if (!criterionJsonElem.isJsonObject())
                    continue;

                JsonObject criterionJson = criterionJsonElem.getAsJsonObject();
                if (!criterionJson.has(SelectorGenerator.TYPE) ||
                        !criterionJson.get(SelectorGenerator.TYPE).getAsString().equals(Type.IP_PROTO.toString()))
                    continue;

                // set 0x84 always
                criterionJson.addProperty(SelectorGenerator.PROTOCOL, IpProtocol.SCTP.getIpProtocolNumber());

                return;
            }

            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, Type.IP_PROTO.toString());
            criterionJson.addProperty(SelectorGenerator.PROTOCOL, IpProtocol.SCTP.getIpProtocolNumber());
            criteriaJson.add(criterionJson);
        }
    }

    private static class RandomSelectorSctp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.SCTP_PORT, FuzzUtil.randomTpPort(rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatSctp implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final TpCriterion tpCriterion = (TpCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.SCTP_PORT, tpCriterion.port());
        }
    }

    /** SCTP MASK **/
    private static class RandomSelectorSctpMask implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.SCTP_PORT, FuzzUtil.randomTpPort(rand));
            criterionJson.addProperty(SelectorGenerator.SCTP_MASK, FuzzUtil.randomTpPort(rand));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatSctpMask implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final TpCriterion tpCriterion = (TpCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.SCTP_PORT, tpCriterion.port());
            criterionJson.addProperty(SelectorGenerator.SCTP_MASK, tpCriterion.mask());
        }
    }

    /** ICMP TYPE **/
    private static class PreRequisiteIcmp implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {

            // generate IpProto-prerequisite (0x800 or 0x86dd) First
            PreRequisiteIp generator = new PreRequisiteIp();
            generator.randomCriterion(type, criteriaJson);

            // icmp (type or code) requires ipProto as 0x1
            for (JsonElement criterionJsonElem : criteriaJson) {
                if (!criterionJsonElem.isJsonObject())
                    continue;

                JsonObject criterionJson = criterionJsonElem.getAsJsonObject();
                if (!criterionJson.has(SelectorGenerator.TYPE) ||
                        !criterionJson.get(SelectorGenerator.TYPE).getAsString().equals(Type.IP_PROTO.toString()))
                    continue;

                // set 0x1 always
                criterionJson.addProperty(SelectorGenerator.PROTOCOL, IpProtocol.ICMP.getIpProtocolNumber());

                return;
            }

            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, Type.IP_PROTO.toString());
            criterionJson.addProperty(SelectorGenerator.PROTOCOL, IpProtocol.ICMP.getIpProtocolNumber());
            criteriaJson.add(criterionJson);
        }
    }

    private static class RandomSelectorIcmpV4Type implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.ICMP_TYPE, rand.nextInt(0x100));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatIcmpV4Type implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final IcmpTypeCriterion icmpTypeCriterion = (IcmpTypeCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.ICMP_TYPE, icmpTypeCriterion.icmpType());
        }
    }

    /** ICMP CODE **/
    private static class RandomSelectorIcmpV4Code implements CriterionGenerator {
        @Override
        public void randomCriterion(Type type, JsonArray criteriaJson) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty(TYPE, type.toString());
            criterionJson.addProperty(SelectorGenerator.ICMP_CODE, rand.nextInt(0x100));
            criteriaJson.add(criterionJson);
        }
    }

    private static class FormatIcmpV4Code implements CriterionJsonFormatter {
        @Override
        public void encodeCriterion(JsonObject criterionJson, Criterion criterion) {
            final IcmpCodeCriterion icmpCodeCriterion = (IcmpCodeCriterion) criterion;
            criterionJson.addProperty(SelectorGenerator.ICMP_CODE, icmpCodeCriterion.icmpCode());
        }
    }

//    private static class RandomSelectorIpV6FLabel implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final IPv6FlowLabelCriterion ipv6FlowLabelCriterion =
//                    (IPv6FlowLabelCriterion) criterion;
//            return root.put(CriterionCodec.FLOW_LABEL, ipv6FlowLabelCriterion.flowLabel());
//        }
//    }
//
//    private static class RandomSelectorIcmpV6Type implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final Icmpv6TypeCriterion icmpv6TypeCriterion =
//                    (Icmpv6TypeCriterion) criterion;
//            return root.put(CriterionCodec.ICMPV6_TYPE, icmpv6TypeCriterion.icmpv6Type());
//        }
//    }
//
//    private static class RandomSelectorIcmpV6Code implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final Icmpv6CodeCriterion icmpv6CodeCriterion =
//                    (Icmpv6CodeCriterion) criterion;
//            return root.put(CriterionCodec.ICMPV6_CODE, icmpv6CodeCriterion.icmpv6Code());
//        }
//    }
//
//    private static class RandomSelectorV6NDTarget implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final IPv6NDTargetAddressCriterion ipv6NDTargetAddressCriterion
//                    = (IPv6NDTargetAddressCriterion) criterion;
//            return root.put(CriterionCodec.TARGET_ADDRESS, ipv6NDTargetAddressCriterion.targetAddress().toString());
//        }
//    }
//
//    private static class RandomSelectorV6NDTll implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final IPv6NDLinkLayerAddressCriterion ipv6NDLinkLayerAddressCriterion
//                    = (IPv6NDLinkLayerAddressCriterion) criterion;
//            return root.put(CriterionCodec.MAC, ipv6NDLinkLayerAddressCriterion.mac().toString());
//        }
//    }
//
//    private static class RandomSelectorMplsLabel implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final MplsCriterion mplsCriterion =
//                    (MplsCriterion) criterion;
//            return root.put(CriterionCodec.LABEL, mplsCriterion.label().toInt());
//        }
//    }
//
//    private static class RandomSelectorMplsBos implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final MplsBosCriterion mplsBosCriterion =
//                    (MplsBosCriterion) criterion;
//            return root.put(CriterionCodec.BOS, mplsBosCriterion.mplsBos());
//        }
//    }
//
//    private static class RandomSelectorIpV6Exthdr implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final IPv6ExthdrFlagsCriterion exthdrCriterion =
//                    (IPv6ExthdrFlagsCriterion) criterion;
//            return root.put(CriterionCodec.EXT_HDR_FLAGS, exthdrCriterion.exthdrFlags());
//        }
//    }
//
//    private static class RandomSelectorOchSigId implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            OchSignal ochSignal = ((OchSignalCriterion) criterion).lambda();
//            ObjectNode child = root.putObject(CriterionCodec.OCH_SIGNAL_ID);
//
//            child.put(CriterionCodec.GRID_TYPE, ochSignal.gridType().name());
//            child.put(CriterionCodec.CHANNEL_SPACING, ochSignal.channelSpacing().name());
//            child.put(CriterionCodec.SPACING_MULIPLIER, ochSignal.spacingMultiplier());
//            child.put(CriterionCodec.SLOT_GRANULARITY, ochSignal.slotGranularity());
//
//            return root;
//        }
//    }
//
//    private static class RandomSelectorOchSigType implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final OchSignalTypeCriterion ochSignalTypeCriterion =
//                    (OchSignalTypeCriterion) criterion;
//            return root.put(CriterionCodec.OCH_SIGNAL_TYPE, ochSignalTypeCriterion.signalType().name());
//        }
//    }
//
//    private static class RandomSelectorTunnelId implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final TunnelIdCriterion tunnelIdCriterion =
//                    (TunnelIdCriterion) criterion;
//            return root.put(CriterionCodec.TUNNEL_ID, tunnelIdCriterion.tunnelId());
//        }
//    }
//
//    private static class RandomSelectorOduSignalId implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            OduSignalId oduSignalId = ((OduSignalIdCriterion) criterion).oduSignalId();
//            ObjectNode child = root.putObject(CriterionCodec.ODU_SIGNAL_ID);
//
//            child.put(CriterionCodec.TRIBUTARY_PORT_NUMBER, oduSignalId.tributaryPortNumber());
//            child.put(CriterionCodec.TRIBUTARY_SLOT_LEN, oduSignalId.tributarySlotLength());
//            child.put(CriterionCodec.TRIBUTARY_SLOT_BITMAP, HexString.toHexString(oduSignalId.tributarySlotBitmap()));
//
//            return root;
//        }
//    }
//
//
//    private static class RandomSelectorOduSignalType implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final OduSignalTypeCriterion oduSignalTypeCriterion =
//                    (OduSignalTypeCriterion) criterion;
//            return root.put(CriterionCodec.ODU_SIGNAL_TYPE, oduSignalTypeCriterion.signalType().name());
//        }
//    }
//
//    private ObjectNode parsePiMatchExact(PiExactFieldMatch exactFieldMatch) {
//
//        ObjectNode matchExactNode = context.mapper().createObjectNode();
//        matchExactNode.put(CriterionCodec.PI_MATCH_FIELD_ID, exactFieldMatch.fieldId().id());
//        matchExactNode.put(CriterionCodec.PI_MATCH_TYPE, PiMatchType.EXACT.name().toLowerCase());
//        matchExactNode.put(CriterionCodec.PI_MATCH_VALUE,
//                HexString.toHexString(exactFieldMatch.value().asArray(),
//                        null));
//        return matchExactNode;
//    }
//
//    private ObjectNode parsePiMatchLpm(PiLpmFieldMatch lpmFieldMatch) {
//
//        ObjectNode matchLpmNode = context.mapper().createObjectNode();
//        matchLpmNode.put(CriterionCodec.PI_MATCH_FIELD_ID, lpmFieldMatch.fieldId().id());
//        matchLpmNode.put(CriterionCodec.PI_MATCH_TYPE, PiMatchType.LPM.name().toLowerCase());
//        matchLpmNode.put(CriterionCodec.PI_MATCH_VALUE,
//                HexString.toHexString(lpmFieldMatch.value().asArray(),
//                        null));
//        matchLpmNode.put(CriterionCodec.PI_MATCH_PREFIX, lpmFieldMatch.prefixLength());
//
//        return matchLpmNode;
//    }
//
//    private ObjectNode parsePiMatchTernary(PiTernaryFieldMatch ternaryFieldMatch) {
//
//        ObjectNode matchTernaryNode = context.mapper().createObjectNode();
//        matchTernaryNode.put(CriterionCodec.PI_MATCH_FIELD_ID, ternaryFieldMatch.fieldId().id());
//        matchTernaryNode.put(CriterionCodec.PI_MATCH_TYPE, PiMatchType.TERNARY.name().toLowerCase());
//        matchTernaryNode.put(CriterionCodec.PI_MATCH_VALUE,
//                HexString.toHexString(ternaryFieldMatch.value().asArray(),
//                        null));
//        matchTernaryNode.put(CriterionCodec.PI_MATCH_MASK,
//                HexString.toHexString(ternaryFieldMatch.mask().asArray(),
//                        null));
//
//        return matchTernaryNode;
//    }
//
//    private ObjectNode parsePiMatchRange(PiRangeFieldMatch rangeFieldMatch) {
//
//        ObjectNode matchRangeNode = context.mapper().createObjectNode();
//        matchRangeNode.put(CriterionCodec.PI_MATCH_FIELD_ID, rangeFieldMatch.fieldId().id());
//        matchRangeNode.put(CriterionCodec.PI_MATCH_TYPE, PiMatchType.RANGE.name().toLowerCase());
//        matchRangeNode.put(CriterionCodec.PI_MATCH_HIGH_VALUE,
//                HexString.toHexString(rangeFieldMatch.highValue().asArray(),
//                        null));
//        matchRangeNode.put(CriterionCodec.PI_MATCH_LOW_VALUE,
//                HexString.toHexString(rangeFieldMatch.lowValue().asArray(),
//                        null));
//
//        return matchRangeNode;
//    }
//
//    private class RandomSelectorProtocolIndependent implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            final PiCriterion piCriterion = (PiCriterion) criterion;
//            ArrayNode matchNodes = context.mapper().createArrayNode();
//            for (PiFieldMatch fieldMatch : piCriterion.fieldMatches()) {
//                switch (fieldMatch.type()) {
//                    case EXACT:
//                        matchNodes.add(parsePiMatchExact((PiExactFieldMatch) fieldMatch));
//                        break;
//                    case LPM:
//                        matchNodes.add(parsePiMatchLpm((PiLpmFieldMatch) fieldMatch));
//                        break;
//                    case TERNARY:
//                        matchNodes.add(parsePiMatchTernary((PiTernaryFieldMatch) fieldMatch));
//                        break;
//                    case RANGE:
//                        matchNodes.add(parsePiMatchRange((PiRangeFieldMatch) fieldMatch));
//                        break;
//                    default:
//                        throw new IllegalArgumentException("Type " + fieldMatch.type().name() + " is unsupported");
//                }
//            }
//            return (ObjectNode) root.set(CriterionCodec.PI_MATCHES, matchNodes);
//        }
//    }
//
//    private class RandomSelectorExtension implements CriterionGenerator {
//        @Override
//        public void randomCriterion(Type type, JsonArray criteriaJson) {
//            Output output = new Output(new ByteArrayOutputStream());
//            KryoNamespaces.API.borrow().writeObject(output, criterion);
//            root.put(CriterionCodec.EXTENSION, output.toBytes());
//            output.flush();
//            output.close();
//
//            return root;
//        }
//    }
}
