package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion.Type;

import java.io.UnsupportedEncodingException;
import java.util.Objects;

public class IcmpCodeCriterion implements Criterion {
    private static final short MASK = 0xff;
    private short icmpCode;           // The ICMP code: 8 bits
    private Type type;

    /**
     * Constructor.
     *
     * @param icmpCode the ICMP code to match (8 bits unsigned integer)
     */
    IcmpCodeCriterion(short icmpCode) {
        this.icmpCode = (short) (icmpCode & MASK);
    }

    public IcmpCodeCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, NumberFormatException {
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.ICMPV4_CODE.toString()))
                type = Type.ICMPV4_CODE;
            else
                throw new UnsupportedEncodingException();
        }

        if (jsonObject.has("icmpCode")) {
            icmpCode = (short) (jsonObject.get("icmpCode").getAsInt());
        }
    }

    @Override
    public Type type() {
        return Type.ICMPV4_TYPE;
    }

    /**
     * Gets the ICMP code to match.
     *
     * @return the ICMP code to match (8 bits unsigned integer)
     */
    public short icmpCode() {
        return icmpCode;
    }
}
