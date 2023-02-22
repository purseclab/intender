package edu.purdue.cs.pursec.ifuzzer.searchservice;

import com.rabbitmq.client.AMQP.Channel.Flow;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.FlowRuleStore;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.PathWrapper;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.ReachabilityTree;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.ReachabilityIntent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.searchservice.PathService.Iface;
import org.apache.thrift.TException;
import org.apache.thrift.server.TServer;
import org.apache.thrift.server.TServer.Args;
import org.apache.thrift.server.TSimpleServer;
import org.apache.thrift.transport.TServerSocket;
import org.apache.thrift.transport.TServerTransport;
import org.apache.thrift.transport.TTransportException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class PathServer implements Iface, Runnable {

    private static Logger log = LoggerFactory.getLogger(PathServer.class);
    @SuppressWarnings("rawtypes")
    public  PathService.Processor processor;

    private final TimeManager timeManager = new TimeManager();;
    private TServerTransport serverTransport;
    private TServer server;
//    private FlowRuleStore flowRuleStore;
    private volatile ReachabilityTree reachabilityTree;
    private static final Object lock = new Object();
    private Thread worker;

    public void initialize(FlowRuleStore flowRuleStore) {
//        this.flowRuleStore = flowRuleStore;
        synchronized (lock) {
            reachabilityTree = new ReachabilityTree(flowRuleStore.getNetworkGraph(), flowRuleStore.getInverseNetworkGraph(),
                    flowRuleStore.getFlowRules(), flowRuleStore.getInRuleList(), flowRuleStore.getBoxes(), ConfigConstants.CONFIG_PAZZ_PACKET_HEADER_LEN);
        }
        log.debug("new reachability Tree is calculated!");
        if (worker == null) {
            worker = new Thread(this);
            worker.start();
        }
    }

    @Override
    public List<String> findPaths(String dpid, int egressPort, String packetheader) throws TException {
        //System.out.println("received a request, processing.... egressport is "+egressPort);
        synchronized (lock) {
            long startTimeNano = System.nanoTime( );
            PathWrapper wrapper = this.reachabilityTree.findReversePath(dpid, egressPort, packetheader);
            log.debug("Sending the result, the result is " + wrapper.pathAndPortStrings().toString());
            long taskTimeNano  = System.nanoTime( ) - startTimeNano;
            timeManager.append(taskTimeNano);
            return wrapper.pathAndPortStrings();
        }
    }

    @Override
    public void run() {
        try {
            processor = new PathService.Processor(this);
            serverTransport = new TServerSocket(9090);
            server = new TSimpleServer(new Args(serverTransport).processor(processor));
            //System.out.println("Starting the pathserver...");
            server.serve();
        } catch (TTransportException e) {
            e.printStackTrace();
        }
    }
}
