package edu.purdue.cs.pursec.ifuzzer;

import edu.purdue.cs.pursec.ifuzzer.api.MQReceiver;
import edu.purdue.cs.pursec.ifuzzer.impl.MQReceiverImpl;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class TopologyListenerService {
    private static Logger log = LoggerFactory.getLogger(TopologyListenerService.class);
    private static TopoGraph topoGraph;
    private final MQReceiver receiver;

    public TopologyListenerService(TopoGraph topoGraph) {
        this.topoGraph = topoGraph;

        initializeTopo(topoGraph);

        // Register MQReceiver
        receiver = new MQReceiverImpl(topoGraph);
    }

    public void start() {
        receiver.start();
    }

    private static void initializeTopo(TopoGraph topoGraph) {
        try {
            String body = ONOSUtil.getDevicesFromONOS();
            ONOSUtil.storeGraph(topoGraph, body);

            body = ONOSUtil.getLinksFromONOS();
            ONOSUtil.storeGraph(topoGraph, body);

            body = ONOSUtil.getHostsFromONOS();
            ONOSUtil.storeGraph(topoGraph, body);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
