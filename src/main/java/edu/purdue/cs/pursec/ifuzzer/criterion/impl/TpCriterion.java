package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;

import java.io.UnsupportedEncodingException;

public class TpCriterion implements Criterion {
    private int port;
    private int mask;
    private Type type;

    public TpCriterion(JsonObject jsonObject) throws UnsupportedEncodingException {
        String protoStr = "";
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.TCP_SRC.toString())) {
                type = Type.TCP_SRC;
                protoStr = "tcp";
            } else if (typeStr.equals(Type.TCP_DST.toString())) {
                type = Type.TCP_DST;
                protoStr = "tcp";
            } else if (typeStr.equals(Type.TCP_SRC_MASKED.toString())) {
                type = Type.TCP_SRC_MASKED;
                protoStr = "tcp";
            } else if (typeStr.equals(Type.TCP_DST_MASKED.toString())) {
                type = Type.TCP_DST_MASKED;
                protoStr = "tcp";
            } else if (typeStr.equals(Type.UDP_SRC.toString())) {
                type = Type.UDP_SRC;
                protoStr = "udp";
            } else if (typeStr.equals(Type.UDP_DST.toString())) {
                type = Type.UDP_DST;
                protoStr = "udp";
            } else if (typeStr.equals(Type.UDP_SRC_MASKED.toString())) {
                type = Type.UDP_SRC_MASKED;
                protoStr = "udp";
            } else if (typeStr.equals(Type.UDP_DST_MASKED.toString())) {
                type = Type.UDP_DST_MASKED;
                protoStr = "udp";
            } else if (typeStr.equals(Type.SCTP_SRC.toString())) {
                type = Type.SCTP_SRC;
                protoStr = "sctp";
            } else if (typeStr.equals(Type.SCTP_DST.toString())) {
                type = Type.SCTP_DST;
                protoStr = "sctp";
            } else if (typeStr.equals(Type.SCTP_SRC_MASKED.toString())) {
                type = Type.SCTP_SRC_MASKED;
                protoStr = "sctp";
            } else if (typeStr.equals(Type.SCTP_DST_MASKED.toString())) {
                type = Type.SCTP_DST_MASKED;
                protoStr = "sctp";
            } else {
                throw new UnsupportedEncodingException();
            }
        }

        if (jsonObject.has(protoStr + "Port")) {
            port = jsonObject.get(protoStr + "Port").getAsInt();
        }

        if (jsonObject.has(protoStr + "Mask")) {
            mask = jsonObject.get(protoStr + "Mask").getAsInt();
        } else {
            mask = -1;
        }
    }

    @Override
    public Type type() {
        return this.type;
    }

    public int port() {
        return this.port;
    }

    public int mask() {
        return this.mask;
    }
}
