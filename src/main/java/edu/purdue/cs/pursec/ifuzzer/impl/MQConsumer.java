package edu.purdue.cs.pursec.ifuzzer.impl;

import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import edu.purdue.cs.pursec.ifuzzer.api.MQConstants;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.MQUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class MQConsumer extends DefaultConsumer {
    private static Logger log = LoggerFactory.getLogger(MQConsumer.class);
    private TopoGraph topoGraph;

    public MQConsumer(Channel channel, TopoGraph topoGraph) {
        super(channel);
        this.topoGraph = topoGraph;
    }

    @Override
    public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties,
                               byte[] body) throws IOException {
        Map<String, Object> props = new HashMap<String, Object>();
        if (properties != null && properties.getHeaders() != null) {
            for (Map.Entry<String, Object> e : properties.getHeaders().entrySet()) {
                props.put(e.getKey(), e.getValue().toString());
            }
        }
        String message = new String(body, MQConstants.UTF);
        // skip uninterested events
//        if (MQUtil.isEventMessage("PACKET_IN", message) ||
//                MQUtil.isEventMessage("PORT_STATS_UPDATED", message))
//            return;

        // TODO: request link to get port information
        try {
            MQUtil.storeGraph(topoGraph, message);
        } catch (JsonIOException | JsonSyntaxException ignored) {
        }
//        log.debug(" [x] Received ':" + message + "'");
//        consumeMessageAndDispaly("device_event", message);
//        System.out.println(" [x] Received ':" + message + "'");
    }

//    private void consumeMessageAndDispaly(final String eventType, String message) {
//        JsonObject newJObject = JsonParser.parseString(message).getAsJsonObject();
//        if (newJObject.get("sub_event_type") != null
//                && newJObject.get("sub_event_type").getAsString().equalsIgnoreCase(eventType)) {
//            System.out.println(" [x] Received ':" + newJObject + "'");
//        } else if (newJObject.get("sub_event_type") != null
//                && newJObject.get("sub_event_type").getAsString().equalsIgnoreCase(eventType)) {
//            System.out.println(" [x] Received ':" + newJObject + "'");
//        } else if (newJObject.get("event_type") != null
//                && newJObject.get("event_type").getAsString().equalsIgnoreCase(eventType)) {
//            System.out.println(" [x] Received ':" + newJObject + "'");
//        } else if (newJObject.get("type") != null
//                && newJObject.get("type").getAsString().equalsIgnoreCase(eventType)) {
//            System.out.println(
//                    " [x] Received ':" + newJObject + "'");
//        } else if (newJObject.get("msg_type") != null
//                && newJObject.get("msg_type").getAsString().equalsIgnoreCase(eventType)) {
//            System.out.println(
//                    " [x] Received ':" + newJObject + "'");
//        } else {
//            System.out.println(" [x] Received ':" + newJObject + "'");
//        }
//    }
}
