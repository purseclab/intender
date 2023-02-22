package edu.purdue.cs.pursec.ifuzzer.net.intent.impl;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ONOSConstants;
import edu.purdue.cs.pursec.ifuzzer.api.TestConstants;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion.Type;
import edu.purdue.cs.pursec.ifuzzer.criterion.impl.*;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ResourceElem;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public abstract class ReachabilityIntent<E extends ResourceElem> implements Intent {
    private List<E> srcList;
    private List<E> dstList;
    private State state;
    private String key;
    private int priority;
    private List<Criterion> criteriaList = new ArrayList<>();

    public ReachabilityIntent(int priority) {
        this.srcList = new ArrayList<E>();
        this.dstList = new ArrayList<E>();
        this.key = UUID.randomUUID().toString();
        this.priority = priority;
    }

    public ReachabilityIntent(Intent intent) {
        this.srcList = new ArrayList<E>();
        this.dstList = new ArrayList<E>();
        this.key = intent.getKey();
        this.priority = intent.getPriority();
    }

    public ReachabilityIntent(JsonObject jObject) throws UnsupportedEncodingException, NumberFormatException {
        this.srcList = new ArrayList<E>();
        this.dstList = new ArrayList<E>();

        if (jObject.has("key"))
            this.key = jObject.get("key").getAsString();

        if (jObject.has("priority"))
            this.priority = jObject.get("priority").getAsInt();
        else
            this.priority = ONOSConstants.ONOS_INTENT_DEFAULT_PRIORITY;

        if (jObject.has("state"))
            this.state = State.onosOf(jObject.get("state").getAsString());

        if (jObject.has("selector") &&
                jObject.get("selector").isJsonObject()) {
            JsonObject selectorJson = jObject.get("selector").getAsJsonObject();

            if (selectorJson.has("criteria")) {
                JsonArray criteriaJson = selectorJson.get("criteria").getAsJsonArray();

                for (JsonElement criterionJsonElem : criteriaJson) {
                    JsonObject criterionJson = criterionJsonElem.getAsJsonObject();

                    if (criterionJson.has("type")) {
                        String typeStr = criterionJson.get("type").getAsString();
                        if (typeStr.equals(Type.IN_PORT.toString()) ||
                                typeStr.equals(Type.IN_PHY_PORT.toString())) {
                            criteriaList.add(new PortCriterion(criterionJson));

                        } else if (typeStr.equals(Type.ETH_SRC.toString()) ||
                                typeStr.equals(Type.ETH_DST.toString()) ||
                                typeStr.equals(Type.ETH_SRC_MASKED.toString()) ||
                                typeStr.equals(Type.ETH_DST_MASKED.toString())) {
                            criteriaList.add(new EthCriterion(criterionJson));

                        } else if (typeStr.equals(Type.ETH_TYPE.toString())) {
                            criteriaList.add(new EthTypeCriterion(criterionJson));

                        } else if (typeStr.equals(Type.IPV4_SRC.toString()) ||
                                typeStr.equals(Type.IPV4_DST.toString())) {
                            criteriaList.add(new IPCriterion(criterionJson));

                        } else if (typeStr.equals(Type.TCP_SRC.toString()) ||
                                typeStr.equals(Type.TCP_SRC_MASKED.toString()) ||
                                typeStr.equals(Type.TCP_DST.toString()) ||
                                typeStr.equals(Type.TCP_DST_MASKED.toString()) ||
                                typeStr.equals(Type.UDP_SRC.toString()) ||
                                typeStr.equals(Type.UDP_SRC_MASKED.toString()) ||
                                typeStr.equals(Type.UDP_DST.toString()) ||
                                typeStr.equals(Type.UDP_DST_MASKED.toString()) ||
                                typeStr.equals(Type.SCTP_SRC.toString()) ||
                                typeStr.equals(Type.SCTP_SRC_MASKED.toString()) ||
                                typeStr.equals(Type.SCTP_DST.toString()) ||
                                typeStr.equals(Type.SCTP_DST_MASKED.toString())) {
                            criteriaList.add(new TpCriterion(criterionJson));

                        } else if (typeStr.equals(Type.ICMPV4_CODE.toString())) {
                            criteriaList.add(new IcmpCodeCriterion(criterionJson));

                        } else if (typeStr.equals(Type.ICMPV4_TYPE.toString())) {
                            criteriaList.add(new IcmpTypeCriterion(criterionJson));

                        } else if (typeStr.equals(Type.IP_PROTO.toString())) {
                            criteriaList.add(new IPProtoCriterion(criterionJson));

                        } else if (typeStr.equals(Type.IP_DSCP.toString())) {
                            criteriaList.add(new IPDscpCriterion(criterionJson));

                        } else if (typeStr.equals(Type.IP_ECN.toString())) {
                            criteriaList.add(new IPEcnCriterion(criterionJson));

                        } else if (typeStr.equals(Type.VLAN_VID.toString()) ||
                                typeStr.equals(Type.INNER_VLAN_VID.toString())) {
                            criteriaList.add(new VlanIdCriterion(criterionJson));

                        } else if (typeStr.equals(Type.VLAN_PCP.toString()) ||
                                typeStr.equals(Type.INNER_VLAN_PCP.toString())) {
                            criteriaList.add(new VlanPcpCriterion(criterionJson));

                        }

                    } else {
                        throw new UnsupportedEncodingException();
                    }
                }
            }
        }
    }

    public E getSrc() {
        if (srcList.isEmpty())
            return null;
        return srcList.get(0);
    }

    public E getDst() {
        if (dstList.isEmpty())
            return null;
        return dstList.get(0);
    }

    public void setSrc(E src) {
        if (!srcList.isEmpty())
            srcList.clear();
        srcList.add(src);
    }

    public void addSrc(E src) {
        srcList.add(src);
    }

    public void setDst(E dst) {
        if (!dstList.isEmpty())
            dstList.clear();
        dstList.add(dst);
    }

    public void addDst(E dst) {
        dstList.add(dst);
    }

    public List<E> getSrcList() {
        return srcList;
    }

    public List<E> getDstList() {
        return dstList;
    }

    @Override
    public void setKey(String key) {
        this.key = key;
    }

    @Override
    public String getKey() {
        return key;
    }

    @Override
    public State getState() {
        return state;
    }

    @Override
    public void setState(State state) {
        this.state = state;
    }

    @Override
    public int getPriority() {
        return priority;
    }

    @Override
    public void setPriority(int priority) {
        this.priority = priority;
    }

    public List<Criterion> getCriteriaList() {
        return criteriaList;
    }

    public JsonObject toTestJson(TopoGraph topoGraph) {
        SelectorGenerator generator = new SelectorGenerator();

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("key", getKey());
        jsonObject.addProperty("ret_url", TestConstants.TEST_MANAGER_URL + TestConstants.TEST_RET_ROUTE);
        JsonArray jsonArray = new JsonArray();
        // TODO: cannot encode criterion.
        for (Criterion criterion : this.criteriaList) {
            JsonObject criterionJson = new JsonObject();
            criterionJson.addProperty("type", criterion.type().toString());
            generator.encodeCriterion(criterionJson, criterion);
            jsonArray.add(criterionJson);
        }
        jsonObject.add("criteria", jsonArray);
        return jsonObject;
    }

    @Override
    public boolean equalsConfig(Intent intent) {
        if (!(intent instanceof ReachabilityIntent))
            return false;

        ReachabilityIntent rIntent = (ReachabilityIntent) intent;

        if (!this.key.equals(rIntent.key)) {
            if (!Long.decode(this.key).equals(Long.decode(rIntent.key)))
                return false;
        }

        if (this.priority != rIntent.priority)
            return false;

        /* TODO: support criteria */
//        if (!this.criteriaList.equals(rIntent.criteriaList))
//            return false;

        return true;
    }

    public abstract String getRESTRoute();
}
