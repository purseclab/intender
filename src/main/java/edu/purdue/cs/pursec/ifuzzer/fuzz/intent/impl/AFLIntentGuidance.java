package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl;

import com.google.gson.*;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.*;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CoverageGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.SingleIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionIntentContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.apache.commons.io.FileUtils;

import javax.annotation.Nonnull;
import java.io.*;
import java.net.URL;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class AFLIntentGuidance implements FuzzIntentGuidance {
    /** The size of the "coverage" map that will be sent to AFL. */

    public static File aflDir;
    private static final Properties properties;
    private String afl_a2j_path, afl_j2a_path;
    private File a2jFile;
    private File j2aFile;
    private File pipeDir;
    private InputStream proxyInput;
    private OutputStream proxyOutput;
    private InputStreamReader currentInputStream;
    /** The bits that will be communicated to the AFL proxy. */
    protected ByteBuffer feedback;
    private static final int FEEDBACK_BUFFER_SIZE = 1 << 17;
    private static final byte[] FEEDBACK_ZEROS = new byte[FEEDBACK_BUFFER_SIZE];
    protected List<String> seedStrings = new ArrayList<>();
    private CodeCoverage globalCoverage;

    private SingleIntentFuzzResult fuzzResult;
    private Map<Integer, Integer> responseMap;
    private int numErrors = 0, numUniqueErrors = 0;
    private CoverageGuidance ccg;

    // AFL process
    Process aflProc;

    static {
        Properties fallback = new Properties();
        fallback.put("key", "default");
        properties = new Properties(fallback);

        URL url = TestUtil.class.getClassLoader().getResource(FuzzConstants.FUZZ_AFL_PROP_NAME);
        if (url == null) throw new UncheckedIOException(new FileNotFoundException(FuzzConstants.FUZZ_AFL_PROP_NAME));

        try (InputStream is = url.openStream()) { properties.load(is); }
        catch (IOException e) { throw new UncheckedIOException("Failed to load resource", e); }
    }

    public AFLIntentGuidance() {
        aflDir = new File(System.getenv("AFL_DIR"));
        if (!aflDir.isDirectory()) {
            System.err.printf("AFL_DIR: %s is not directory\n", aflDir.getAbsolutePath());
            System.exit(2);
        }

        this.afl_a2j_path = properties.getProperty(FuzzConstants.FUZZ_AFL_A2J);
        this.afl_j2a_path = properties.getProperty(FuzzConstants.FUZZ_AFL_J2A);

        this.feedback = ByteBuffer.allocate(FEEDBACK_BUFFER_SIZE);
        this.feedback.order(ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public boolean init(Object o) throws IOException, InterruptedException {
        fuzzResult = new SingleIntentFuzzResult();
        responseMap = new HashMap<>();
        globalCoverage = new CodeCoverage();
        ccg = new CoverageGuidance();

        if (ConfigConstants.CONFIG_RUN_FUZZING_IN_LOCAL)
            return true;

        // mkfifo is os-dependent
        a2jFile = new File(afl_a2j_path);
        System.out.println("GET file");
        if (!a2jFile.exists()) {
            Process p = Runtime.getRuntime().exec("mkfifo " + afl_a2j_path);
            int exitCode = p.waitFor();
            System.out.printf("%d: $ mkfifo %s\n", exitCode, afl_a2j_path);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            reader.lines().forEach(System.err::println);

            a2jFile = new File(afl_a2j_path);
        }
        a2jFile.setWritable(true, false);

        j2aFile = new File(afl_j2a_path);
        if (!j2aFile.exists()) {
            Process p = Runtime.getRuntime().exec("mkfifo " + afl_j2a_path);
            int exitCode = p.waitFor();
            System.out.printf("%d: $ mkfifo %s\n", exitCode, afl_j2a_path);

            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            reader.lines().forEach(System.err::println);

            j2aFile = new File(afl_j2a_path);
        }
        j2aFile.setWritable(true, false);

        return true;
    }

    public boolean start(String seed) throws IOException {
        // 1. Create inputDir
        File inputDir = new File("/tmp/ifuzzer/seed/");
        if (!inputDir.exists()) {
            // create directory
            if (!inputDir.mkdir())
                return false;
        } else {
            // clean directory
            FileUtils.cleanDirectory(inputDir);
        }

        // 2. Create new seed file in inputDir
        if (seedStrings.size() == 0)
            seedStrings.add(seed);

        for (int i = 0; i < seedStrings.size(); i++) {
            String seedFile = String.format("/tmp/ifuzzer/seed/input_%03d.txt", i);

            try (FileWriter fileWriter = new FileWriter(seedFile)) {
                fileWriter.write(seedStrings.get(i));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (!ConfigConstants.CONFIG_RUN_FUZZING_IN_LOCAL) {
            File outputDir = new File(IFuzzer.rootPath + File.separator + "scenarios/afl-" +
                    LocalDateTime.now().format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS"))));
            if (outputDir.exists()) {
                FileUtils.cleanDirectory(outputDir);
            } else {
                if (!outputDir.mkdir())
                    return false;
            }

            // 3. Execute afl-fuzz -i {inputDir} {afl-intender}
            File aflLogFile = new File("/tmp/ifuzzer/afl.log");
            ProcessBuilder aflProcBuilder = new ProcessBuilder();
            Map<String, String> aflProcEnv = aflProcBuilder.environment();
            aflProcEnv.put("AFL_SKIP_BIN_CHECK", "1");
            aflProcEnv.put("AFL_NO_AFFINITY", "1");
            aflProcEnv.put("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1");
            aflProcEnv.put("AFL_SKIP_CPUFREQ", "1");

            aflProcBuilder.command(aflDir.getAbsolutePath() + File.separator + "afl-fuzz",
                    "-i", inputDir.getAbsolutePath(),
                    "-o", outputDir.getAbsolutePath(),
                    "-m", "4096",
                    "-t", "50+",
                    IFuzzer.rootPath + "/agents/afl-agent/afl-intender",
                    "-a", "@@");        // @@ is the location of input file given by AFL
            aflProcBuilder.redirectOutput(aflLogFile);
            aflProcBuilder.redirectError(aflLogFile);

            aflProc = aflProcBuilder.start();

            System.out.printf("AFL process is%s running\n", aflProc.isAlive() ? "" : " not");

        } else {
            try {
                // FIXME
                while (true) {
                    String pipeDirLocation;
                    try {
                        BufferedReader reader = new BufferedReader(new FileReader(
                                IFuzzer.rootPath + "/agents/afl-agent/pipe.txt"));
                        pipeDirLocation = reader.readLine();
                        reader.close();

                    } catch (Exception e) {
                        TimeUnit.MILLISECONDS.sleep(10);
                        continue;
                    }

                    if (pipeDirLocation == null) {
                        TimeUnit.MILLISECONDS.sleep(10);
                        continue;
                    }

                    pipeDir = new File(pipeDirLocation);

                    a2jFile = new File(pipeDirLocation + File.separator + "a2j-pipe");
                    j2aFile = new File(pipeDirLocation + File.separator + "j2a-pipe");

                    if (a2jFile.exists() && !j2aFile.exists())
                        break;
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        // 4. Open named pipes
        proxyInput = new BufferedInputStream(new FileInputStream(a2jFile));
        System.out.println("InputStream is opened.");
        proxyOutput = new BufferedOutputStream(new FileOutputStream(j2aFile));
        System.out.println("OutputStream is opened.");

        return true;
    }

    @Override
    public boolean stop() {
        if (aflProc != null) {
            aflProc.destroy();
            aflProc = null;
        }

        if (proxyInput != null || proxyOutput != null) {
            try {
                proxyInput.close();
                proxyOutput.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

            proxyInput = null;
            proxyOutput = null;
        }

        if (pipeDir != null) {
            if (!pipeDir.delete())
                return false;
        } else {
            if (a2jFile != null && !a2jFile.delete())
                return false;
            if (j2aFile != null && !j2aFile.delete())
                return false;
        }

        seedStrings.clear();

        return true;
    }

    @Override
    public String getRandomIntentJson(String targetJsonStr)
            throws IOException, JsonIOException, JsonSyntaxException {

        String type = null;
        if (ConfigConstants.CONFIG_FUZZING_TYPE_INVARIANCE) {
            JsonObject targetJson = JsonParser.parseString(targetJsonStr).getAsJsonObject();
            type = targetJson.remove("type").getAsString();
            targetJsonStr = targetJson.toString();
        }
        // check whether afl process is running or not
        if (proxyInput == null || proxyOutput == null) {
            start(targetJsonStr);
        }

        if (!hasInput())
            throw new NotActiveException("AFL-proxy is not ready");

        BufferedReader reader = new BufferedReader(new FileReader(
                IFuzzer.rootPath + "/agents/afl-agent/input.txt"));
        String input = reader.readLine();
        reader.close();

        byte[] encoded = Files.readAllBytes(Paths.get(input));
        String newJsonStr = new String(encoded, StandardCharsets.US_ASCII);

        if (ConfigConstants.CONFIG_FUZZING_TYPE_INVARIANCE) {
            JsonObject newJson = JsonParser.parseString(newJsonStr).getAsJsonObject();
            newJson.addProperty("type", type);
            newJsonStr = newJson.toString();
        }

        return newJsonStr;
    }

    @Override
    public boolean feedbackResult(@Nonnull FuzzScenario parentScenario) {
        CodeCoverage codeCoverage = parentScenario.getCodeCoverage();

        if (proxyInput == null || proxyOutput == null)
            return false;

        if (codeCoverage == null)
            return false;

        /*** WRITE COVERAGE INTO J2A ***/
        System.out.println("send result");

        try {
            if (currentInputStream != null) {
                currentInputStream.close();
                currentInputStream = null;
            }
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        // Reset the feedback buffer for a new run
        clearFeedbackBuffer();

        // Send the status value to AFL
        feedback.putInt(getStatusCode(SingleIntentFuzzResult.getStatus(parentScenario)));

        // Send trace-bits to AFL as a contiguous array
        codeCoverage.putBitmap(feedback);

        // Send feedback to AFL
        try {
            proxyOutput.write(feedback.array(), 0, feedback.position());
            proxyOutput.flush();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        globalCoverage.updateCoverage(codeCoverage);
        if (parentScenario.isError()) {
            numErrors ++;
            if (ccg.isUniqueCrash(codeCoverage) > 0) {
                numUniqueErrors ++;
            }
        }

        // add results
        int code = SingleIntentGuidance.getIntentReqStatusCode(parentScenario);
        if (code > 0)
            responseMap.put(code, responseMap.getOrDefault(code, 0) + 1);
        fuzzResult.addSingleIntentResult(parentScenario);

        return true;
    }

    private boolean hasInput() {
        boolean ret = true;
        // Get a 4-byte signal from AFL
        byte[] signal = new byte[4];
        try {
            int received = proxyInput.read(signal, 0, 4);
            //System.out.printf("READ %d char\n", received);
            if (received != 4) {
                throw new IOException("Could not read `ready` from AFL");
            }


        } catch (IOException e) {
            ret = false;
        }

        return ret;
    }

    /** Clears the feedback buffer by resetting it to zero. */
    protected void clearFeedbackBuffer() {
        // These redundant casts are to prevent Java 9's covariant
        // return types to use the new methods that return ByteBuffer
        // instead, which do not exist in JDK 8 and below.
        ((Buffer) feedback).rewind();
        feedback.put(FEEDBACK_ZEROS);
        ((Buffer) feedback).rewind();
    }

    @Override
    public boolean isCoverageGuided() {
        return true;
    }

    @Override
    public boolean doesRequireLogging(FuzzScenario scenario) {
        if (!scenario.isFuzzed())
            return false;

        if (!scenario.isAccepted()) {
            int code = SingleIntentGuidance.getIntentReqStatusCode(scenario);
            if (code >= 200 && code < 300) {
                return true;
            } else if (responseMap.getOrDefault(code, 0) <= 1) {
                return true;
            }
        } else {
            String intentStr = SingleIntentGuidance.getIntentStr(scenario);
            try {
                JsonObject intentJson = TestUtil.fromJson(intentStr);
            } catch (Exception e) {
                // unlikely ...
                return true;
            }
        }

        if (scenario.isVerified())
            return true;

        return false;
    }

    @Override
    public String getStatsHeader() {
        return CodeCoverage.getStatsHeader()
                + ", " + SingleIntentFuzzResult.getStatsHeader()
                + ", errors, uniqueErrors";
    }

    @Override
    public String getStatsString() {
        StringBuilder builder = new StringBuilder().append(globalCoverage.getStatsString());
        builder.append(", ").append(fuzzResult.getStatsString());
        builder.append(", ").append(numErrors);
        builder.append(", ").append(numUniqueErrors);
        return builder.toString();
    }

    @Override
    public String getResultsString() {
        return fuzzResult.getResultsString();
    }

    @Override
    public void addSeeds(Collection<FuzzAction> fuzzActions) {
        for (FuzzAction fuzzAction : fuzzActions) {
            if (fuzzAction.getContent() instanceof FuzzActionIntentContent) {

                // copy content from the seed
                FuzzActionIntentContent fuzzActionIntentContent = (FuzzActionIntentContent) fuzzAction.getContent();
                seedStrings.add(fuzzActionIntentContent.getIntent());
            }
        }
    }

    public int getStatusCode(FuzzResult.RetStatus retStatus) {
        switch (retStatus) {
            case SUCCESS:
                return 0;
            case FAILURE:
                return 6;
            case INVALID:
                return 1 << 8;
            default:
                break;
        }

        return 0;
    }
}
