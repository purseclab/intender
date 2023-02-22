package edu.purdue.cs.pursec.ifuzzer.cli;


import com.google.common.collect.Lists;
import com.google.gson.*;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.tools.ExecFileLoader;
import org.jline.reader.Completer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Command(name = "replay", mixinStandardHelpOptions = true)
public class ReplayCommand implements Runnable {

    private final int byteBufferSize = 1 << 16;

    @ParentCommand
    CliCommands parent;

    // TODO: make ibn-fuzzer home dir environment (IBNF_HOME)
    static final String failedPath = System.getProperty("user.dir") +
            File.separator + "scenarios" + File.separator + "failure";
    public static TopologyIntentGuidance localTopoGuidance;

    public ReplayCommand() {}

    @Parameters(index= "0", arity = "1..*", description = "at least one file", defaultValue = "ALL",
            completionCandidates = ReplayCandidates.class)
    String[] fileNames;
    @Option(names = "-n", description = "repeat count", defaultValue = "1")
    int repeat_count;
    @Option(names = "-i", description = "interactive mode")
    boolean isInteractive;
    @Option(names = "-t", description = "run all intents for given topology", defaultValue = "false")
    boolean topoAwareMode;

    // Support auto-completion file arguments
    static class ReplayCandidates implements Iterable<String> {
        @Override
        public Iterator<String> iterator() {
            File scenarioDir = new File(failedPath);
            if (!scenarioDir.isDirectory())
                return Collections.emptyIterator();

            File[] scenarioFiles = scenarioDir.listFiles(File::isFile);
            if (scenarioFiles == null || scenarioFiles.length == 0)
                return Collections.emptyIterator();

            return (Arrays.stream(scenarioFiles)
                    .map(File::getName)
                    .collect(Collectors.toList())
                    .iterator());
        }
    }

    @Override
    public void run() {
        List<File> scenarioFiles;

        if (fileNames[0].equals("ALL")) {
            // Get all scenarios
            File scenarioDir = new File(failedPath);
            if (!scenarioDir.isDirectory()) {
                parent.out.printf("Error: cannot find path %s\n", failedPath);
                return;
            }
            try {
                scenarioFiles = Files.walk(Paths.get(failedPath))
                        .filter(Files::isRegularFile)
                        .map(Path::toFile)
                        .collect(Collectors.toList());
            } catch (IOException ioe) {
                parent.out.printf("Error: %s\n", ioe.toString());
                return;
            }
        } else {
            // Get file
            List<File> files = Arrays.stream(fileNames)
                    .map(s -> failedPath + File.separator + s)
                    .filter(k -> !k.contains(".."))
                    .map(File::new)
                    .collect(Collectors.toList());

            scenarioFiles = new ArrayList<>();
            for (File file : files) {
                if (file.isFile()) {
                    // add regular files
                    scenarioFiles.add(file);
                } else if (file.isDirectory()) {
                    // add regular files in directory
                    try {
                        scenarioFiles.addAll(Files.walk(Paths.get(file.getPath()))
                                .filter(Files::isRegularFile)
                                .map(Path::toFile)
                                .filter(k -> !k.getPath().endsWith(".swp"))
                                .collect(Collectors.toList()));
                    } catch (IOException ioe) {
                        parent.out.printf("Error: %s\n", ioe.toString());
                        return;
                    }
                }
            }
        }

        Queue<FuzzScenario> scenarioList = new LinkedList<>();
        for (File scenarioFile : scenarioFiles) {
            try {
                JsonObject scenarioJson = TestUtil.fromJson(new FileReader(scenarioFile));
                if (scenarioJson != null) {
                    FuzzScenario scenario = new FuzzScenario(scenarioJson);
                    scenarioList.add(scenario);
                }
            } catch (Exception e) {
                e.printStackTrace();
                parent.out.printf("Error while reading %s: %s\n", scenarioFile, e.getMessage());
            }
        }

        parent.out.printf("REPLAY %d scenarios\n", scenarioList.size());

        // Disable isInteractive when repeat count is bigger than 1
        if (repeat_count > 1)
            isInteractive = false;

        if (topoAwareMode) {
            try {
                localTopoGuidance = new TopologyIntentGuidance();
                localTopoGuidance.init(parent.topoGraph);
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(2);
            }
        }

        // Main Loop: Execute scenarios
        Map<List<Byte>, Integer> traceMaps = new HashMap<>();
        FuzzScenario scenario = null;

        CodeCoverage aggregateCov = new CodeCoverage();
        while (!scenarioList.isEmpty()) {
            scenario = scenarioList.poll();
            for (int i = 0; i < repeat_count; i++) {
                if (i > 0)
                    scenario = FuzzScenario.copy(scenario);

                if (isInteractive) {
                    /* disable completer */
                    Completer completer = parent.reader.getCompleter();
                    parent.reader.setCompleter(null);

                    // TODO: do not save y/n in history
                    parent.scenarioStore.execute(scenario, parent.reader);

                    /* refresh */
                    parent.reader.setCompleter(completer);
                } else {
                    parent.scenarioStore.execute(scenario);
                }
                parent.out.printf("[%d/%d] %s\n", i+1, repeat_count, scenario.getResult());
                parent.out.flush();

                if (!isInteractive) {
                    ExecFileLoader loader = scenario.getCodeCoverage().getLoader();
                    Byte[] traceBits = FuzzUtil.getCoverageBitmaps(loader, byteBufferSize);
                    List<Byte> traceBitList = Lists.newArrayList(traceBits);
                    traceMaps.compute(traceBitList, (k, v) -> (v == null) ? 1 : v + 1);
                }

                if (ConfigConstants.CONFIG_REPLAY_CODE_COVERAGE_INCLUSIVE)
                    aggregateCov.updateCoverage(scenario.getCodeCoverage());
                else
                    aggregateCov.diffCoverage(scenario.getCodeCoverage());
            }

            if (topoAwareMode) {
                try {
                    // Fuzz it
                    scenarioList.add(FuzzScenario.fuzz(scenario));
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (EndFuzzException e) {
                    /** stop fuzz **/
                    if (scenario != null && ConfigConstants.CONFIG_ENABLE_COVERAGE_LOGGING) {
                        storeScenario(scenario, true);
                    }
                    scenarioList.clear();
                }
            } else if (!isInteractive && !ConfigConstants.CONFIG_REPLAY_CODE_COVERAGE_INCLUSIVE) {
                storeScenario(scenario, aggregateCov);
            }
        }

        if (topoAwareMode) {
            localTopoGuidance.stop();
        }

        if (ConfigConstants.CONFIG_REPLAY_CODE_COVERAGE_INCLUSIVE) {
            storeScenario(scenario, aggregateCov);
        }

        if (scenario != null)
            parent.scenarioStore.revertAllConfigTopoOperations(scenario);

        parent.out.printf("[REPLAY RESULT] %d/%d paths\n", traceMaps.keySet().size(), repeat_count);
    }



    private void storeScenario(FuzzScenario scenario, boolean storeGlobalCoverage) {

        CodeCoverage codeCoverage = scenario.getCodeCoverage();
        if (storeGlobalCoverage && localTopoGuidance != null) {
            if (localTopoGuidance.getCodeCoverage() != null)
                codeCoverage = localTopoGuidance.getCodeCoverage();
        }

        storeScenario(scenario, codeCoverage);
    }

    private void storeScenario(FuzzScenario scenario, CodeCoverage codeCoverage) {
        ExecFileLoader loader = codeCoverage.getLoader();

        // log failed scenario
        String curDate = LocalDateTime.now()
                .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));

        String replayDirPath = failedPath + File.separator + curDate;
        File replayDir = new File(replayDirPath);
        if (!replayDir.exists()) {
            if (!replayDir.mkdir()) {
                System.err.printf("Cannot create %s\n", replayDirPath);
                System.exit(2);
            }
        }

        try {
            // 1) write JSON
            FileWriter fileWriter = new FileWriter(replayDirPath + File.separator + "input.json");
            Gson gson = new Gson();
            gson.toJson(scenario.toJsonObject(), fileWriter);
            fileWriter.flush();
            fileWriter.close();

            // 2) write jacoco.exec
            loader.save(new File(replayDirPath + File.separator + "coverage.exec"), false);

            // 3) write bitmap (hash id)
            ByteBuffer feedback = ByteBuffer.allocate(byteBufferSize);
            feedback.order(ByteOrder.LITTLE_ENDIAN);
            Byte[] traceBits = FuzzUtil.getCoverageBitmaps(loader, byteBufferSize);

            for (int i = 0; i < byteBufferSize; i++) {
                feedback.put(traceBits[i]);
            }

            OutputStream fw = new BufferedOutputStream(new FileOutputStream(replayDirPath + File.separator + "bitmap.out"));
            fw.write(feedback.array(), 0, feedback.position());
            fw.flush();
            fw.close();

            // 4) write bitmap (string id)
            BufferedReader classFileReader = new BufferedReader(new FileReader(ONOSUtil.getONOSClassListFilePath()));
            Map<String, Integer> classMap = new HashMap<>();

            PrintStream pw = new PrintStream(new File(replayDirPath + File.separator + "coverage.out"));

            String clLine;
            while ((clLine = classFileReader.readLine()) != null) {
                classMap.put(clLine, 0);
            }

            for (ExecutionData data : loader.getExecutionDataStore().getContents()) {
                int cnt = 0;
                for (boolean probe : data.getProbes()) {
                    if (probe)
                        cnt++;
                }
                int ret = classMap.getOrDefault(data.getName(), -1);

                pw.println(String.format("[%s] %s: %d", ret < 0 ? "X" : "O", data.getName(), cnt));
            }
            pw.close();

            // 5) stat.out
            File statFile = new File(replayDirPath + File.separator + "stat.out");
            PrintStream statOut = new PrintStream(statFile);
            statOut.println(CodeCoverage.getStatsHeader());
            statOut.println(codeCoverage.getStatsString());
            statOut.flush();
            statOut.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
