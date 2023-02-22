package edu.purdue.cs.pursec.ifuzzer.util;

import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.api.MQConstants;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoDevice;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoEdge;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoGraphEvent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoElem.State;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class MQUtil {
    private static final Logger log = LoggerFactory.getLogger(MQUtil.class);
    private MQUtil() {}

    public static String getRabbitMQServerURL(String protocol, String userName, String password, String ipAddress,
                                               String port, String vhost) {

        StringBuilder urlBuilder = new StringBuilder();
        try {
            urlBuilder.append(protocol).append("://").append(userName).append(":").append(password).append("@")
                    .append(ipAddress).append(":").append(port).append("/").append(URLEncoder.encode(vhost, MQConstants.UTF));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return urlBuilder.toString().replaceAll("\\s+", "");
    }

//    public static boolean isEventMessage(final String eventType, String message) {
//        JsonObject jObject = JsonParser.parseString(message).getAsJsonObject();
//        return isEventMessage(eventType, jObject);
//    }

    public static boolean isEventMessage(final String eventType, JsonObject jObject) {
        if (jObject.get("sub_event_type") != null
                && jObject.get("sub_event_type").getAsString().equalsIgnoreCase(eventType)) {
            return true;
        } else if (jObject.get("sub_event_type") != null
                && jObject.get("sub_event_type").getAsString().equalsIgnoreCase(eventType)) {
            return true;
        } else if (jObject.get("event_type") != null
                && jObject.get("event_type").getAsString().equalsIgnoreCase(eventType)) {
            return true;
        } else if (jObject.get("type") != null
                && jObject.get("type").getAsString().equalsIgnoreCase(eventType)) {
            return true;
        } else if (jObject.get("msg_type") != null
                && jObject.get("msg_type").getAsString().equalsIgnoreCase(eventType)) {
            return true;
        }

        return false;
    }

    public static void storeGraph(TopoGraph topoGraph, String message) throws JsonSyntaxException, JsonIOException {
        JsonObject jObject = TestUtil.fromJson(message);
        if (isEventMessage("DEVICE_ADDED", jObject)) {
            topoGraph.addNode(new TopoDevice(jObject));

        } else if (isEventMessage("DEVICE_AVAILABILITY_CHANGED", jObject)) {
            TopoDevice dev = (TopoDevice) topoGraph.getNode(TopoDevice.getId(jObject));
            if (dev != null) {
                topoGraph.updateStateNode(dev.getState().reverse(), dev);
            }

        } else if (isEventMessage("LINK_ADDED", jObject)) {
            try {
                String body = ONOSUtil.getLinksFromONOS();
                ONOSUtil.storeGraph(topoGraph, body);
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else if (isEventMessage("LINK_REMOVED", jObject)) {
            String srcId = null, dstId = null;
            if (jObject.has("src"))
                srcId = jObject.get("src").getAsString();

            if (jObject.has("dst"))
                dstId = jObject.get("dst").getAsString();

            // TODO: support multilink
            TopoEdge edge = topoGraph.getEdgeFromNodes(srcId, dstId);
            if (edge != null) {
                topoGraph.updateStateEdge(State.INACTIVE, edge.getId());
            }
        } else if (isEventMessage("LINK_UPDATED", jObject)) {
            String srcId = null, dstId = null;
            if (jObject.has("src"))
                srcId = jObject.get("src").getAsString();

            if (jObject.has("dst"))
                dstId = jObject.get("dst").getAsString();

            // TODO: support multilink
            TopoEdge edge = topoGraph.getEdgeFromNodes(srcId, dstId);
            if (edge != null) {
                if (jObject.has("state")) {
                    String state = jObject.get("state").getAsString();
                    topoGraph.updateStateEdge(State.of(state.toUpperCase()), edge.getId());
                }
            }
        }
    }

    public static TopoGraphEvent.Type topoStateToEventType (State state) {
        if (state.equals(State.ACTIVE))
            return TopoGraphEvent.Type.PUT;

        return TopoGraphEvent.Type.REMOVE;
    }
}
