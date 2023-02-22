package edu.purdue.cs.pursec.ifuzzer.cli;

import edu.purdue.cs.pursec.ifuzzer.cli.ConfigTopologyCommand.TopoEdgeCommand;
import edu.purdue.cs.pursec.ifuzzer.cli.ConfigTopologyCommand.TopoNodeCommand;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.ParentCommand;

import java.util.Random;

@Command(name = "topo-config", mixinStandardHelpOptions = true,
        subcommands = {TopoNodeCommand.class, TopoEdgeCommand.class,
                CommandLine.HelpCommand.class})
public class ConfigTopologyCommand implements Runnable {

    @ParentCommand CliCommands parent;
    static Random rand = new Random();

    public ConfigTopologyCommand() {}

    @Command(name = "get")
    public void printTopo() {
        TopoGraph graph = TopoGraph.getConfigTopology();
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
            TopoGraph graph = TopoGraph.getConfigTopology();
            graph.getAllNodes().forEach(node -> System.out.println(node.toString()));
        }

        @Override
        public void run() { System.out.println("subcommands: {get}"); }
    }

    @Command(name = "edge", subcommands = {CommandLine.HelpCommand.class})
    static class TopoEdgeCommand implements Runnable {

        @Command(name = "get")
        public void printEdges() {
            TopoGraph graph = TopoGraph.getConfigTopology();
            graph.getAllEdges().forEach(edge -> System.out.println(edge.toString()));
            graph.getAllTempEdges().forEach(edge -> System.out.println("[T] " + edge.toString()));
        }

        @Override
        public void run() { System.out.println("subcommands: {get, load, fuzz}"); }
    }
}
