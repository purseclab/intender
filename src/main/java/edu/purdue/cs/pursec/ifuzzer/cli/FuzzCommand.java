package edu.purdue.cs.pursec.ifuzzer.cli;


import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.FuzzResult;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.GuidanceException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.SingleIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore.*;

@Command(name = "fuzz", mixinStandardHelpOptions = true)
public class FuzzCommand implements Runnable {
    private static final Logger log = LoggerFactory.getLogger(FuzzCommand.class);
    @ParentCommand
    CliCommands parent;

    // TODO: make ibn-fuzzer home dir environment (IBNF_HOME)
    static final String scenarioPath = System.getProperty("user.dir") +
            File.separator + "scenarios";

    public FuzzCommand() {}

    @Option(names = "-f", description = "fuzz run count", defaultValue = "0")
    int fuzz_count;
    @Option(names = "-n", description = "repeat count", defaultValue = "1")
    int repeat_count;
    @Option(names = "-t", description = "execution time", defaultValue = "PT0S")
    Duration execDuration;
    @Option(names = "-q", description = "quiet mode", defaultValue = "false")
    boolean quietMode;

    @Parameters(index= "0", arity = "1..*", description = "at least one file", defaultValue = "ALL",
            completionCandidates = FuzzCandidates.class)
    String[] fileNames;

    String failedPath = scenarioPath + File.separator + "failure";
    public static String logDir;
    public static PrintStream statOut;

    // Support auto-completion file arguments
    static class FuzzCandidates implements Iterable<String> {
        @Override
        public Iterator<String> iterator() {
            File scenarioDir = new File(scenarioPath);
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

        /* read files */
        if (fileNames[0].equals("ALL")) {
            // Get all scenarios
            File scenarioDir = new File(scenarioPath);
            if (!scenarioDir.isDirectory()) {
                parent.out.printf("Error: cannot find path %s\n", scenarioPath);
                return;
            }
            try {
                scenarioFiles = Files.walk(Paths.get(scenarioPath))
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
                    .map(s -> scenarioPath + File.separator + s)
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

        /* read scenarios from given files */
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

        if (!quietMode) {
            String curDate = LocalDateTime.now()
                    .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));

            logDir = scenarioPath + File.separator + curDate;
            failedPath = logDir + File.separator + "failure";
            File replayDir = new File(logDir);
            if (!replayDir.exists()) {
                if (!replayDir.mkdir()) {
                    System.err.printf("Cannot create %s\n", logDir);
                    System.exit(2);
                }
            }

            try {
                File statFile = new File(logDir + File.separator + "stat.out");
                statOut = new PrintStream(statFile);
                statOut.println(scenarioGuidance.getStatsHeader());
                statOut.flush();
            } catch (IOException e) {
                e.printStackTrace();
                System.exit(2);
            }

            File failedDir = new File(failedPath);
            if (!failedDir.exists()) {
                if (!failedDir.mkdir()) {
                    System.err.printf("Cannot create %s\n", failedPath);
                    System.exit(2);
                }
            }

            // TODO: store current config
        }

        /* initialize guidance */
        try {
            if (scenarioGuidance instanceof SingleIntentGuidance) {
                scenarioGuidance.addSeeds(scenarioList);
            }
            scenarioGuidance.init(parent.configTopoGraph);
            globalTopoGuidance.init(parent.topoGraph);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(2);
        }

        FuzzResult totalResult = new FuzzResult();
        FuzzResult fuzzResult = new FuzzResult();
        LocalDateTime startDate = LocalDateTime.now();
        boolean updateDate = true;

        /** Main Loop: Execute scenarios **/
        FuzzScenario scenario = null;
        while (!scenarioList.isEmpty()) {
            scenario = scenarioList.poll();

            if (scenario.getFuzzCnt() == 1 && updateDate) {
                startDate = LocalDateTime.now();
                updateDate = false;
            }

            for (int i = 0; i < repeat_count; i++) {
                if (i > 0) {
                    scenario = FuzzScenario.copy(scenario);             // COPY
                }

                // EXECUTE IT !
                String errorMsg = parent.scenarioStore.execute(scenario);
                totalResult.addResult(scenario, errorMsg);
                if (scenario.isFuzzed())
                    fuzzResult.addResult(scenario, errorMsg);

                if (errorMsg == null) {
                    parent.out.printf("%s\n\n", scenario.getResult());
                    parent.out.flush();

                } else {
                    parent.out.println(errorMsg);
                    parent.out.println();
                    return;
                }

                // While giving feedback, scenario could be truncated.
                parent.scenarioStore.feedbackResult(scenario);

                // Try to store it, always.
                storeScenario(scenario);
            }

            while (true) {
                try {
                    if (scenario.stopFuzz()) {
                        scenarioList.clear();
                        break;
                    }

                    if (fuzz_count < 0 || scenario.getFuzzCnt() < fuzz_count ||
                            Duration.between(startDate, LocalDateTime.now()).compareTo(execDuration) < 0) {
                        scenarioList.add(FuzzScenario.fuzz(scenario));      // FUZZ
                    }

                } catch (IOException e) {
                    e.printStackTrace();

                } catch (JsonSyntaxException e) {
                    scenario.incFuzzCnt();
                    totalResult.addResult(e);
                    if (scenario.isFuzzed())
                        fuzzResult.addResult(e);
                    continue;

                } catch (EndFuzzException | GuidanceException e) {
                    log.warn("Stop fuzz by exception", e);
                    // stop fuzz
                    scenarioList.clear();
                }

                break;
            }
        }
        scenarioGuidance.stop();

        if (scenario != null)
            parent.scenarioStore.revertAllConfigTopoOperations(scenario);

        String totalResultStr = "[TOTAL] " + totalResult.getSummary() + " (" +
                Duration.between(startDate, LocalDateTime.now()).toString() + ")";
        String fuzzResultStr = "[FUZZ] " + fuzzResult.getSummary() + " (" +
                Duration.between(startDate, LocalDateTime.now()).toString() + ")";

        parent.out.println(totalResultStr);
        parent.out.println(fuzzResultStr);

        if (!quietMode) {
            try {
                File resultFile = new File(logDir + File.separator + "result.out");
                PrintStream resultOut = new PrintStream(resultFile);
                resultOut.println(totalResultStr);
                resultOut.println(fuzzResultStr);
                resultOut.println(scenarioGuidance.getResultsString());

                if (statOut != null) {
                    statOut.println(scenarioGuidance.getStatsString());
                    statOut.flush();
                    statOut.close();
                }
                resultOut.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    boolean storeOnce = true;

    private void storeScenario(FuzzScenario scenario) {
        /*
         * TODO: store result.txt and current config (running arg, guidance, etc.)
         */
        boolean logScenario = false;

        // Log scenario
        if (scenario.isFuzzed()) {
            if (scenario.doesRequireLogging()) {
                logScenario = true;
            }

            if (scenario.getFuzzCnt() > 300 && storeOnce) {
                storeOnce = false;
                logScenario = true;
            }
            /*
             * Make log depending on the guidance
             * - NO/Syntax/AFL: log if scenario is verified
             * - Topology: log if scenario is NOT verified
             */
            if (scenarioGuidance.doesRequireLogging(scenario)) {
                logScenario = true;
            }
        }

        // log failed scenario
        if (logScenario) {
            String fileName = LocalDateTime.now()
                    .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS")));
            if (scenario.isUniqueError())
                fileName += "-unique";
            fileName += ".json";
            try (FileWriter fileWriter = new FileWriter(failedPath + File.separator + fileName)) {
                Gson gson = new Gson();
                gson.toJson(scenario.toJsonObject(), fileWriter);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (!quietMode) {
            if (scenario.getFuzzCnt() % ConfigConstants.CONFIG_MEASURE_STAT_INTERVAL == 1) {
                assert (statOut != null);
                statOut.println(scenarioGuidance.getStatsString());
                statOut.flush();
            }
        }
    }
}
