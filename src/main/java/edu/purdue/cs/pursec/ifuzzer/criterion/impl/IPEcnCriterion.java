package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;

import java.io.UnsupportedEncodingException;

public class IPEcnCriterion implements Criterion {
    private static final short MASK = 0x3;
    private byte ipEcn;               // IP ECN value: 2 bits
    private Type type;

    public IPEcnCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, NumberFormatException {
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.IP_ECN.toString()))
                type = Type.IP_ECN;
            else
                throw new UnsupportedEncodingException();
        }

        if (jsonObject.has("ipEcn")) {
            ipEcn = jsonObject.get("ipEcn").getAsByte();
        }
    }

    @Override
    public Type type() {
        return Type.IP_ECN;
    }

    public short ipEcn() {
        return this.ipEcn;
    }
}
