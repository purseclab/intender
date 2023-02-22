package edu.purdue.cs.pursec.ifuzzer.cli;

import edu.purdue.cs.pursec.ifuzzer.cli.TopologyCommand.TopoEdgeCommand;
import edu.purdue.cs.pursec.ifuzzer.cli.TopologyCommand.TopoFlowCommand;
import edu.purdue.cs.pursec.ifuzzer.cli.TopologyCommand.TopoHostCommand;
import edu.purdue.cs.pursec.ifuzzer.cli.TopologyCommand.TopoNodeCommand;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.FlowRuleStore;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoHost;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.*;

@Command(name = "topo", mixinStandardHelpOptions = true,
        subcommands = {TopoNodeCommand.class, TopoEdgeCommand.class,
        TopoHostCommand.class, TopoFlowCommand.class, CommandLine.HelpCommand.class})
public class TopologyCommand implements Runnable {

    @ParentCommand CliCommands parent;
    static Random rand = new Random();

    public TopologyCommand() {}

    @Command(name = "get")
    public void printTopo() {
        TopoGraph graph = TopoGraph.getOperationalTopology();
        graph.getAllElem().forEach(elem -> System.out.println(elem.toString()));
    }

    @Override
    public void run() {
        parent.out.println("subcommands: {get, node, edge}");
    }

    @Command(name = "node", subcommands = {CommandLine.HelpCommand.class})
    static class TopoNodeCommand implements Runnable {

        @Command(name = "get")
        public void printNodes() {
            TopoGraph graph = TopoGraph.getOperationalTopology();
            graph.getAllNodes().forEach(node -> System.out.println(node.toString()));
        }

        @Override
        public void run() { System.out.println("subcommands: {get}"); }
    }

    @Command(name = "edge", subcommands = {CommandLine.HelpCommand.class})
    static class TopoEdgeCommand implements Runnable {

        @Command(name = "get")
        public void printEdges() {
            TopoGraph graph = TopoGraph.getOperationalTopology();
            graph.getAllEdges().forEach(edge -> System.out.println(edge.toString()));
            graph.getAllTempEdges().forEach(edge -> System.out.println("[T] " + edge.toString()));
        }

        @Command(name = "load")
        public void loadEdges() {
            TopoGraph graph = TopoGraph.getOperationalTopology();
            try {
                String body = ONOSUtil.getLinksFromONOS();
                System.out.println(body);
                ONOSUtil.storeGraph(graph, body);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() { System.out.println("subcommands: {get, load, fuzz}"); }
    }

    @Command(name = "host", subcommands = {CommandLine.HelpCommand.class})
    static class TopoHostCommand implements Runnable {

        @Command(name = "load")
        public void loadHosts() {
            TopoGraph graph = TopoGraph.getOperationalTopology();
            //graph.getAllEdges().forEach(edge -> System.out.println(edge.toString()));
            try {
                String body = ONOSUtil.getHostsFromONOS();
                System.out.println(body);
                ONOSUtil.storeGraph(graph, body);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        @Command(name = "pingall")
        public void pingAllHosts() {
            try {
                HttpURLConnection conn = TestUtil.requestPingAll();
                if (conn.getResponseCode() >= 200 && conn.getResponseCode() < 300)
                    System.out.println("done");
                else
                    System.out.println("failed");

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Command(name = "ping")
        public void ping(@Parameters(arity = "2", description = "hosts") String[] hosts) {
            TopoGraph graph = TopoGraph.getOperationalTopology();

            TopoHost hostNode1 = (TopoHost) graph.getNode(hosts[0]);
            TopoHost hostNode2 = (TopoHost) graph.getNode(hosts[1]);
            try {
                if (TestUtil.requestPing(hostNode1, hostNode2))
                    System.out.println("done");
                else
                    System.out.println("failed");

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        @Override
        public void run() { System.out.println("subcommands: {load, ping, pingall}"); }
    }

    @Command(name = "flow", subcommands = {CommandLine.HelpCommand.class})
    static class TopoFlowCommand implements Runnable {

        @Command(name = "get")
        public void printFlows() {
            FlowRuleStore ruleStore = FlowRuleStore.getInstance();
            ruleStore.getFlowRules().values().forEach(rule -> System.out.println(rule.toString()));
        }

        @Override
        public void run() { System.out.println("subcommands: {get}"); }
    }
}
