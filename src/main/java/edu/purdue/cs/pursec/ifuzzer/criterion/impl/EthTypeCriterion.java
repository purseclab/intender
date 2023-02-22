package edu.purdue.cs.pursec.ifuzzer.criterion.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;
import org.projectfloodlight.openflow.types.EthType;

import java.io.UnsupportedEncodingException;

public class EthTypeCriterion implements Criterion {
    private EthType ethType;
    private Type type;

    public EthTypeCriterion(JsonObject jsonObject) throws UnsupportedEncodingException, NumberFormatException {
        if (jsonObject.has("type")) {
            String typeStr = jsonObject.get("type").getAsString();
            if (typeStr.equals(Type.ETH_TYPE.toString()))
                type = Type.ETH_TYPE;
            else
                throw new UnsupportedEncodingException();
        }

        if (jsonObject.has("ethType")) {
            String ethTypeStr = jsonObject.get("ethType").getAsString();
            int ethTypeValue;
            if (ethTypeStr.startsWith("0x"))
                ethTypeValue = Integer.parseInt(ethTypeStr.substring(2), 16);
            else
                ethTypeValue = Integer.parseInt(ethTypeStr);

            ethType = EthType.of(ethTypeValue);
        }
    }

    @Override
    public Type type() {
        return this.type;
    }

    public EthType ethType() {
        return this.ethType;
    }
}
