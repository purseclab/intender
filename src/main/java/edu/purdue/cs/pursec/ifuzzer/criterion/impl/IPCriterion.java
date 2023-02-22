package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;

import java.io.UnsupportedEncodingException;

public class IPCriterion implements Criterion {
    private IPv4AddressWithMask ip;
    private Type type;

    public IPCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, IllegalArgumentException {
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.IPV4_SRC.toString()))
                type = Type.IPV4_SRC;
            else if (typeStr.equals(Type.IPV4_DST.toString()))
                type = Type.IPV4_DST;
            else
                throw new UnsupportedEncodingException();
        }

        if (jsonObject.has("ip"))
            this.ip = IPv4AddressWithMask.of(jsonObject.get("ip").getAsString());
    }

    @Override
    public Type type() {
        return this.type;
    }

    public IPv4AddressWithMask ip(){
        return this.ip;
    }
}
