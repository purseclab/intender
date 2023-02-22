package edu.purdue.cs.pursec.ifuzzer.net.flow.api;
import com.google.common.primitives.Ints;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.PointToPointIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ResourcePoint;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import jdd.bdd.BDD;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

public class Rule {
    String id;
    String state;
    long dpid;

    /**
     * @author ApoorvShukla and saidjawadsaidi
     *
     */
    int[] in_ports;
    String matchString;
    int out_ports;
    int predicate = 0;
    int[] predicates = new int[7];
    int priority;
    VerifyRuleId rule_id;
    int table_id;


    public Rule(long dpid, String id, String state, int rule_id, int[] in_ports, int out_ports,
                int priority, int table_id, String matchString) {
        this.dpid = dpid;
        this.id = id;
        this.state = state;
        this.rule_id = new VerifyRuleId(dpid, rule_id);
        this.in_ports = in_ports;
        this.out_ports = out_ports;
        this.priority = priority;
        this.table_id = table_id;
        this.matchString = matchString;
    }

    public String getId() {
        return id;
    }

    /**
     * @return
     */
    public int[] getin_ports() {
        return this.in_ports;
    }

    /**
     * @return the matchString
     */
    public String getMatchString() {
        return matchString;
    }

    /**
     * @return
     */
    public int getOutportId() {
        return this.out_ports;
    }

    public int getPredicate() {
        return this.predicate;
    }

    public int[] getPredicates() {
        return predicates;
    }

    public int getPriority() {
        return priority;
    }

    public VerifyRuleId getrule_id() {
        return this.rule_id;
    }

    public int gettable_id() {
        return table_id;
    }

    public void reSetAllPredicates(int predicate) {
        this.predicate = predicate;
        for (int port : in_ports) {
            predicates[port % 10] = predicate;
        }

    }

    public boolean matchesInportId(int portId){
        for(int pId: in_ports){
            if(pId==portId)
                return true;
        }
        return false;
    }

    public long getDpid() {
        return dpid;
    }

    /**
     * @param matchString
     *            the matchString to set
     */
    public void setMatchString(String matchString) {
        this.matchString = matchString;
    }

    public void setPredicateForPort(int portIndex, int predicate) {
        predicates[portIndex] = predicate;
    }

    public void setPriority(int priority) {
        this.priority = priority;
    }

    public void settable_id(int table_id) {
        this.table_id = table_id;
    }
    public void reCalculatePredicate(BDD bdd){
        int predicate = bdd.ref(bdd.minterm(this.matchString));
        this.predicates = new int[7];
        for (int port : in_ports) {
            predicates[port % 10] = predicate;
        }
    }

    @Override
    public String toString() {
        return "{" +
                "id='" + id + '\'' +
                ", state='" + state + '\'' +
                ", dpid='" + dpid + '\'' +
                ", in_ports=" + Arrays.toString(in_ports) +
                ", matchString='" + matchString + '\'' +
                ", out_ports=" + out_ports +
                ", predicate=" + predicate +
                ", predicates=" + Arrays.toString(predicates) +
                ", priority=" + priority +
                ", rule_id=" + rule_id.dump() +
                ", table_id=" + table_id +
                '}';
    }

    public static Rule of(JsonObject jObject) {
        if (jObject == null || !jObject.has("deviceId"))
            return null;

        Builder builder = new Builder();

        String deviceId = jObject.get("deviceId").getAsString();
        builder.setDpid(ONOSUtil.getDpid(deviceId));

        if (jObject.has("id"))
            builder.setId(jObject.get("id").getAsString());

        if (jObject.has("state"))
            builder.setState(jObject.get("state").getAsString());


        if (jObject.has("tableId"))
            builder.setTable_id(jObject.get("tableId").getAsInt());

        if (jObject.has("priority"))
            builder.setPriority(jObject.get("priority").getAsInt());

        if (jObject.has("selector")) {
            JsonObject selectorJson = jObject.get("selector").getAsJsonObject();
            if (selectorJson.has("criteria")) {
                JsonArray criteriaJsonArr = selectorJson.get("criteria").getAsJsonArray();
                for (JsonElement criterionJsonElem : criteriaJsonArr) {
                    JsonObject criterionJson = criterionJsonElem.getAsJsonObject();
                    if (!criterionJson.has("type"))
                        continue;

                    String typeStr = criterionJson.get("type").getAsString();
                    if (typeStr.equals("IN_PORT")) {
                        builder.addInPort(criterionJson.get("port").getAsInt());

                    } else if (typeStr.equals("IPV4_DST")) {
                        // XXX: PAZZ tests only destination-based coverage.
                        IPv4AddressWithMask dstIp = IPv4AddressWithMask.of(criterionJson.get("ip").getAsString());
                        byte[] dstIpBytes = dstIp.getValue().getBytes();
                        int cidrLen = dstIp.getMask().asCidrMaskLength();
                        StringBuilder predicateBuilder = new StringBuilder();
                        for (int i = 0; i < 4; i++) {
                            if (cidrLen >= 8) {
                                predicateBuilder.append(String.format("%8s", Integer.toBinaryString(dstIpBytes[i] & 0xFF))
                                        .replace(' ', '0'));
                                cidrLen -= 8;
                            } else if (cidrLen > 0){
                                predicateBuilder.append(String.format("%8s", Integer.toBinaryString(dstIpBytes[i] & 0xFF))
                                        .replace(' ', '0'), 0, cidrLen);

                                for (int j = 0; j < 8 - cidrLen; j++)
                                    predicateBuilder.append('-');
                                cidrLen = 0;
                            } else {
                                for (int j = 0; j < 8; j++)
                                    predicateBuilder.append('-');
                            }
                        }
                        builder.setMatchString(predicateBuilder.toString());
                    }
                }
            }
        }

        if (jObject.has("treatment")) {
            JsonObject treatmentJson = jObject.get("treatment").getAsJsonObject();
            if (treatmentJson.has("instructions")) {
                JsonArray instJsonArr = treatmentJson.get("instructions").getAsJsonArray();
                for (JsonElement instJsonElem : instJsonArr) {
                    JsonObject instJson = instJsonElem.getAsJsonObject();
                    if (!instJson.has("type"))
                        continue;

                    String typeStr = instJson.get("type").getAsString();
                    if (typeStr.equals("OUTPUT")) {
                        String portStr = instJson.get("port").getAsString();

                        if (portStr.equals("CONTROLLER")) {
                            builder.setOutPorts(-3);
                        } else {
                            builder.setOutPorts(Integer.parseInt(portStr));
                        }

                    } else if (typeStr.equals("L2MODIFICATION") &&
                            instJson.has("subtype") &&
                            instJson.get("subtype").getAsString().equals("TUNNEL_ID")) {
                        long tunnelId = instJson.get("tunnelId").getAsLong();
                        long verifyRuleId = tunnelId >> 32;
                        int verifyPortId = (int) (tunnelId & 0xffffffffL);

                        if (builder.inPorts.contains(verifyPortId)) {
                            builder.setRule_id((int)verifyRuleId);
                        }
                    }
                }
            }
        }

        return builder.build();
    }

    private static class Builder {
        private String id;
        private String state;
        private long dpid;
        private ArrayList<Integer> inPorts = new ArrayList<>();
        private String matchString = null;
        private int outPorts;
        private int priority;
        private int rule_id;
        private int table_id;

        public void setId(String id) {
            this.id = id;
        }

        public void setState(String state) {
            this.state = state;
        }

        public void setDpid(long dpid) {
            this.dpid = dpid;
        }

        public void addInPort(int inPort) {
            this.inPorts.add(inPort);
        }

        public void setMatchString(String matchString) {
            this.matchString = matchString;
        }

        public void setOutPorts(int outPorts) {
            this.outPorts = outPorts;
        }

        public void setPriority(int priority) {
            this.priority = priority;
        }

        public void setRule_id(int rule_id) {
            this.rule_id = rule_id;
        }

        public void setTable_id(int table_id) {
            this.table_id = table_id;
        }

        public Rule build() {
            if (inPorts.size() == 0)
                return null;

            return new Rule(dpid, id, state, rule_id, Ints.toArray(inPorts), outPorts,
                    priority, table_id, matchString);
        }

    }
}
