package edu.purdue.cs.pursec.ifuzzer.net.topo.impl;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoDevice;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoElem;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoHost;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoLink;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;

import java.util.UUID;

public class TopoOperation {
    public enum Type {
        ADD,
        DELETE,
    }

    Type type;
    TopoElem elem;
    String dpid;
    String port;
    String actionId;
    int seq;
    boolean isInitOperation = false;

    public TopoOperation(Type type, TopoElem elem) {
        this.type = type;
        this.elem = elem;
    }

    public TopoOperation(Type type, TopoElem elem, String dpid) {
        this.type = type;
        this.elem = elem;
        this.dpid = dpid;   // only for topoHost
    }

    public TopoOperation(Type type, TopoElem elem, String dpid, String port) {
        this.type = type;
        this.elem = elem;
        this.dpid = dpid;   // only for topoHost
        this.port = port;   // only for topoHost
    }

    public TopoOperation(FuzzAction fuzzAction) throws IllegalArgumentException {
        String elemType = "";
        String[] actionCmd = fuzzAction.getActionCmd().split("-");
        if (actionCmd.length != 2)
            throw new IllegalArgumentException("invalid action command: " + fuzzAction.getActionCmd());
        elemType = actionCmd[1];

        JsonObject contentJson = fuzzAction.getContent().getContent();
        if (elemType.equals("link")) {
            elem = new TopoLink(contentJson);
        } else if (elemType.equals("device")) {
            elem = new TopoDevice(contentJson);
        } else if (elemType.equals("host")) {
            elem = new TopoHost(contentJson, true);
        } else {
            throw new IllegalArgumentException("invalid action command: " + fuzzAction.getActionCmd());
        }

        if (actionCmd[0].equals(Type.ADD.name().toLowerCase()))
            this.type = Type.ADD;
        else if (actionCmd[0].equals(Type.DELETE.name().toLowerCase()))
            this.type = Type.DELETE;
        else
            throw new IllegalArgumentException("invalid action command: " + fuzzAction.getActionCmd());

        if (contentJson.has("dpid"))
            dpid = contentJson.get("dpid").getAsString();

        if (contentJson.has("port"))
            port = contentJson.get("port").getAsString();

        actionId = fuzzAction.getId();
        isInitOperation = fuzzAction.isInitAction();
    }

    public TopoOperation(JsonObject jsonObject) {
        String elemType = "";
        if (jsonObject.has("action")) {
            String[] actionCmd = jsonObject.get("action").getAsString().split("-");
            assert (actionCmd.length == 2);

            if (actionCmd[0].equals(Type.ADD.name().toLowerCase()))
                this.type = Type.ADD;
            else if (actionCmd[0].equals(Type.DELETE.name().toLowerCase()) ||
                        actionCmd[0].equals("del"))
                this.type = Type.DELETE;

            elemType = actionCmd[1];
        }

        if (jsonObject.has("content")) {
            JsonObject contentJson = jsonObject.get("content").getAsJsonObject();
            if (elemType.equals("link")) {
                elem = new TopoLink(contentJson);
            } else if (elemType.equals("device")) {
                elem = new TopoDevice(contentJson);
            } else if (elemType.equals("host")) {
                elem = new TopoHost(contentJson);
            }

            if (contentJson.has("dpid"))
                dpid = contentJson.get("dpid").getAsString();

            if (contentJson.has("port"))
                port = contentJson.get("port").getAsString();
        }

        if (jsonObject.has("init")) {
            isInitOperation = jsonObject.get("init").getAsBoolean();
        }
    }

    public TopoOperation invert() {
        return new TopoOperation(TopoOperation.invertType(this.type),
                this.elem, this.dpid, this.port);
    }

    public static Type invertType(Type type) {
        if (type.equals(Type.ADD)) {
            return Type.DELETE;
        } else {
            return Type.ADD;
        }
    }

    public static boolean isTopoOperation(String actionCmd) {
        String[] cmds = actionCmd.split("-");
        if (cmds.length != 2)
            return false;

        String elemType = cmds[1];
        return elemType.equals("link") || elemType.equals("device") || elemType.equals("host");
    }

    public boolean isInitOperation() {
        return isInitOperation;
    }

    public String getNote() {
        String note = "";
        if (this.elem instanceof TopoDevice) {
            TopoDevice device = (TopoDevice) this.elem;
            note = device.getId();
        } else if (this.elem instanceof TopoLink) {
            TopoLink link = (TopoLink) this.elem;
            note = ONOSUtil.getLinkId(link.getSrcId(), link.getDstId(),
                    link.getSrcPort(), link.getDstPort());
        } else if (this.elem instanceof TopoHost) {
            TopoHost host = (TopoHost) this.elem;
            note = host.getIps().toArray()[0].toString();
        }

        return note;
    }

    public String getDpid() {
        return dpid;
    }

    public void setDpid(String dpid) {
        this.dpid = dpid;
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    public Type getType() {
        return type;
    }

    public TopoElem getElem() {
        return elem;
    }

    public String getActionCmd() {
        return this.getRequestUrl() + "-" + this.getElemType();
    }

    public String getElemType() {
        return (this.getElem().type().toString());
    }

    public String getRequestUrl() {
        return (this.getType().name().toLowerCase());
    }

    public String getRequestMethod() {
        if (this.getType().equals(Type.DELETE)) {
            return "DELETE";
        }

        return "POST";
    }

    public static String getRequestMethod(String cmd) {
        if (cmd.equals("delete")) {
            return "DELETE";
        }

        return "POST";
    }

    public String getActionId() {
        return actionId;
    }

    public void setActionId(String actionId) {
        this.actionId = actionId;
    }

    public int getSeq() {
        return seq;
    }

    public void setSeq(int seq) {
        this.seq = seq;
    }

    public JsonObject toFuzzActionJson() {
        JsonObject fuzzActionJson = new JsonObject();
        fuzzActionJson.addProperty("action", this.getActionCmd());
        JsonObject elemJson = elem.toJson();
        if (dpid != null)
            elemJson.addProperty("dpid", dpid);
        if (port != null)
            elemJson.addProperty("port", port);
        fuzzActionJson.add("content", elemJson);

        return fuzzActionJson;
    }

    public FuzzAction toFuzzAction(String actionId) {
        return new FuzzAction(actionId, this.toFuzzActionJson());
    }

    public FuzzAction toFuzzAction() {
        return new FuzzAction(this.actionId != null ? this.actionId : UUID.randomUUID().toString(),
                this.toFuzzActionJson());
    }

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    public boolean typeEquals(Object obj) {
        if (!(obj instanceof TopoOperation))
            return false;

        TopoOperation topoObj = (TopoOperation) obj;

        if (!this.getRequestUrl().equals(topoObj.getRequestUrl()))
            return false;

        if (!this.getElemType().equals(topoObj.getElemType()))
            return false;

        if (this.getElem() instanceof TopoDevice) {
            TopoDevice thisDevice = (TopoDevice) this.getElem();
            TopoDevice thatDevice = (TopoDevice) topoObj.getElem();

            // DPID is lower-case
            if (!thisDevice.getId().toLowerCase().equals(thatDevice.getId().toLowerCase()))
                return false;

        } else if (this.getElem() instanceof TopoLink) {
            TopoLink thisLink = (TopoLink) this.getElem();
            TopoLink thatLink = (TopoLink) topoObj.getElem();

            boolean isSameLink = false;
            if (thisLink.getDstId().equals(thatLink.getDstId()) &&
                    thisLink.getSrcId().equals(thatLink.getSrcId())) {
                isSameLink = true;
            } else if (thisLink.getSrcId().equals(thatLink.getDstId()) &&
                    thisLink.getDstId().equals(thatLink.getSrcId())) {
                isSameLink = true;
            }

            if (!isSameLink)
                return false;

        } else if (this.getElem() instanceof TopoHost) {
            TopoHost thisHost = (TopoHost) this.getElem();
            TopoHost thatHost = (TopoHost) topoObj.getElem();

            if (!thisHost.getIps().equals(thatHost.getIps()))
                return false;
        }

        // DPID
        if (this.dpid == null && topoObj.dpid != null)
            return false;

        if (this.dpid != null && !this.dpid.equals(topoObj.dpid))
            return false;

        // PORT
        if (this.port == null && topoObj.port != null)
            return false;

        if (this.port != null && !this.port.equals(topoObj.port))
            return false;

        return true;
    }
}
