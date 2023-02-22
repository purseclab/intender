package edu.purdue.cs.pursec.ifuzzer.cli;

import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.SinglePointToMultiPointIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.IntentStore;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.ParentCommand;

import static java.lang.Thread.sleep;

@Command(name = "intent", mixinStandardHelpOptions = true)
public class IntentCommand implements Runnable {

    @ParentCommand CliCommands parent;

    public IntentCommand() {}

    @Command(name = "load")
    public void loadIntent() {

        IntentStore intentStore = IntentStore.getInstance();

        try {
            String body = ONOSUtil.getIntentsFromONOS();
            System.out.println(body);
            intentStore.clear();
            ONOSUtil.storeIntent(intentStore, body);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Command(name = "get")
    public void getIntent() {
        IntentStore intentStore = IntentStore.getInstance();
        intentStore.getAllIntents().forEach(intent -> System.out.println(intent.toString()));
    }

    @Command(name = "random-h2h")
    public void randomH2HIntent() {
        parent.intentFuzzerService.randomHostToHostIntent();
    }

    @Command(name = "random-p2p")
    public void randomP2PIntent() {
        parent.intentFuzzerService.randomPointToPointIntent();
    }

//    @Command(name = "random-sp2mp")
//    public void randomSP2MPIntent() {
//        parent.intentFuzzerService.randomSinglePointToMultiPointIntent();
//    }
//
//    @Command(name = "random-mp2sp")
//    public void randomMP2SPIntent() {
//        parent.intentFuzzerService.randomMultiPointToSinglePointIntent();
//    }

    @Command(name = "replay")
    public void replayIntent() {
        try {
            SinglePointToMultiPointIntent prevIntent = parent.intentFuzzerService.replayOne();
            // TODO: make intent listener
            sleep(3000);
            parent.intentFuzzerService.replayTwo(prevIntent);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        parent.out.println("subcommands: {load, random}");
    }

//    @Command(name = "random", subcommands = {CommandLine.HelpCommand.class})
//    static class IntentRandomCommand implements Runnable {
//
//        @Command(name = "get")
//        public void printEdges() {
//            TopoGraph graph = TopoGraph.getInstance();
//            graph.getAllEdges().forEach(edge -> System.out.println(edge.toString()));
//            graph.getAllTempEdges().forEach(edge -> System.out.println("[T] " + edge.toString()));
//        }
//
//        @Override
//        public void run() { System.out.println("subcommands: {get}"); }
//    }
}
