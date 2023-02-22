package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;

import java.io.UnsupportedEncodingException;
import java.util.Objects;
import java.util.UUID;

public class PortCriterion implements Criterion {
    private long portNo;
    private Type type;

    /**
     * Constructor.
     *
     * @param portNo the input port number to match
     * @param type the match type. Should be either Type.IN_PORT or
     * Type.IN_PHY_PORT
     */
    public PortCriterion(long portNo, Type type) {
        this.portNo = portNo;
        this.type = type;
    }

    public PortCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, NumberFormatException {
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.IN_PORT.toString()))
                type = Type.IN_PORT;
            else if (typeStr.equals(Type.IN_PHY_PORT.toString()))
                type = Type.IN_PHY_PORT;
            else
                throw new UnsupportedEncodingException();
        }

        if (jsonObject.has("port"))
            this.portNo = jsonObject.get("port").getAsLong();
    }

    @Override
    public Type type() {
        return this.type;
    }

    /**
     * Gets the input port number to match.
     *
     * @return the input port number to match
     */
    public long portNo() {
        return this.portNo;
    }
}
