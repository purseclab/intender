package edu.purdue.cs.pursec.ifuzzer.cli;

import edu.purdue.cs.pursec.ifuzzer.IntentFuzzerService;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.FlowRuleStore;
import edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import org.jline.reader.LineReader;
import org.jline.reader.impl.LineReaderImpl;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.io.PrintWriter;

@Command(name = "", description = "Intender interactive shell",
        footer = {"", "Press Ctrl-D to exit."},
        subcommands = {TopologyCommand.class, ConfigTopologyCommand.class,
                IntentCommand.class, FuzzCommand.class, ReplayCommand.class})
public class CliCommands implements Runnable {
    LineReaderImpl reader;
    PrintWriter out;
    final TopoGraph topoGraph, configTopoGraph;
    final IntentFuzzerService intentFuzzerService;
    final ScenarioStore scenarioStore;
    final FlowRuleStore flowRuleStore;

    @Spec
    private CommandSpec spec;

    public CliCommands(TopoGraph topoGraph, TopoGraph configTopoGraph, IntentFuzzerService intentFuzzerService,
                       ScenarioStore scenarioStore, FlowRuleStore flowRuleStore) {
        this.topoGraph = topoGraph;
        this.configTopoGraph = configTopoGraph;
        this.intentFuzzerService = intentFuzzerService;
        this.scenarioStore = scenarioStore;
        this.flowRuleStore = flowRuleStore;
    }

    public void setReader(LineReader reader) {
        assert(reader instanceof LineReaderImpl);
        this.reader = (LineReaderImpl) reader;
        out = reader.getTerminal().writer();
    }

    @Override
    public void run() {
        out.println(new CommandLine(this).getUsageMessage());
    }
}
