package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion.Type;
import org.projectfloodlight.openflow.types.EthType;

import java.io.UnsupportedEncodingException;
import java.util.Objects;

public class IcmpTypeCriterion implements Criterion {
    private static final short MASK = 0xff;
    private short icmpType;           // The ICMP type: 8 bits
    private Type type;

    /**
     * Constructor.
     *
     * @param icmpType the ICMP type to match (8 bits unsigned integer)
     */
    IcmpTypeCriterion(short icmpType) {
        this.icmpType = (short) (icmpType & MASK);
    }

    public IcmpTypeCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, NumberFormatException {
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.ICMPV4_TYPE.toString()))
                type = Type.ICMPV4_TYPE;
            else
                throw new UnsupportedEncodingException();
        }

        if (jsonObject.has("icmpType")) {
            icmpType = (short) (jsonObject.get("icmpType").getAsInt());
        }
    }

    @Override
    public Type type() {
        return Type.ICMPV4_TYPE;
    }

    /**
     * Gets the ICMP type to match.
     *
     * @return the ICMP type to match (8 bits unsigned integer)
     */
    public short icmpType() {
        return icmpType;
    }
}
