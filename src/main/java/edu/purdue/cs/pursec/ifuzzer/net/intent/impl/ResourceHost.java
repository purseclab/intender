package edu.purdue.cs.pursec.ifuzzer.net.intent.impl;

import com.google.gson.Gson;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ResourceElem;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import org.projectfloodlight.openflow.types.MacAddress;

public class ResourceHost implements ResourceElem {
    String hostId;

    public ResourceHost(String hostId) {
        this.hostId = ONOSUtil.getHostId(hostId);
    }

    public String getHostId() {
        return hostId;
    }

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    @Override
    public boolean isValid() {
        return ONOSUtil.isValidHostId(this.hostId);
    }
}
