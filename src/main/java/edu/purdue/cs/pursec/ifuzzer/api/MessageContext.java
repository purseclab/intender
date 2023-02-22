package edu.purdue.cs.pursec.ifuzzer.api;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

public class MessageContext implements Serializable {
    private String sensorId;
    private byte[] body;
    private Map<String, Object> properties = new HashMap<String, Object>();

    public MessageContext(String sensorId, byte[] body) {
        if (sensorId == null) {
            throw new IllegalArgumentException("SensorID should be present");
        }

        if (body == null) {
            throw new IllegalArgumentException("The body should be present");
        }

        this.sensorId = sensorId;
        this.body = body;
    }

    public MessageContext(String sensorId, byte[] body, Map<String, Object> properties) {
        this(sensorId, body);

        if (properties != null)
            this.properties = properties;
    }

    public String getSensorId() {
        return sensorId;
    }

    public byte[] getBody() {
        return body;
    }

    public Map<String, Object> getProperties() {
        return properties;
    }

    public void setSensorId(String sensorId) {
        this.sensorId = sensorId;
    }
}
