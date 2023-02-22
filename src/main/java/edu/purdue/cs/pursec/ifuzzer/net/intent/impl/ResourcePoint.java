package edu.purdue.cs.pursec.ifuzzer.net.intent.impl;

import com.google.gson.Gson;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ResourceElem;

import java.net.URI;

public class ResourcePoint implements ResourceElem {
    String deviceId;
    String portNo;

    public ResourcePoint(String deviceId, String portNo) {
        this.deviceId = deviceId;
        this.portNo = portNo;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public String getPortNo() {
        return portNo;
    }

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    @Override
    public boolean isValid() {
        try {
            // (1) Check deviceId
            // XXX: do we have to check deviceId?
//            if (!deviceId.startsWith("of:"))
//                return false;
//
//            // assume that dpid consists of 16-length hex
//            String dpid = deviceId.substring(3);
//            Long.parseLong(dpid, 16);
            URI.create(deviceId);

            // (2) Check port
            long portLong = Long.parseLong(portNo);
            if (portLong < 0 || portLong > 0xffffffffL)
                return false;

            if (portLong > 0xffffff00L && portLong < 0xfffffff8L)
                return false;

        } catch (Exception e) {
            return false;
        }

        return true;
    }
}
