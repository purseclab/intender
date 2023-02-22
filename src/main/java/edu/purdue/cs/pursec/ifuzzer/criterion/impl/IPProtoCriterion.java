package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;

import java.io.UnsupportedEncodingException;

public class IPProtoCriterion implements Criterion {
    private static final short MASK = 0xff;
    private short proto;
    private Type type;

    public IPProtoCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, NumberFormatException {
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.IP_PROTO.toString()))
                type = Type.IP_PROTO;
            else
                throw new UnsupportedEncodingException();
        }

        if (jsonObject.has("protocol")) {
            proto = (short) (jsonObject.get("protocol").getAsInt());
        }
    }

    @Override
    public Type type() {
        return Type.IP_PROTO;
    }

    /**
     * Gets the ICMP type to match.
     *
     * @return the ICMP type to match (8 bits unsigned integer)
     */
    public short protocol() {
        return this.proto;
    }
}
