/*
 * Copyright 2022 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.FuzzResult;
import edu.purdue.cs.pursec.ifuzzer.api.SingleIntentFuzzResult;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CoverageGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.JavaNames;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.SingleIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionIntentContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.Buffer;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.TimeUnit;

// Copied from com.code_intelligence.jazzer.driver.FuzzTargetRunner
public class JazzerIntentGuidance implements FuzzIntentGuidance {
    private static Logger log = LoggerFactory.getLogger(JazzerIntentGuidance.class);
    private static final String i2j_path = "/tmp/ifuzzer/i2j-pipe";
    private static final String j2i_path = "/tmp/ifuzzer/j2i-pipe";
    private static final int FEEDBACK_BUFFER_SIZE = 1 << 17;
    private static final byte[] FEEDBACK_ZEROS = new byte[FEEDBACK_BUFFER_SIZE];
    private File i2jFile, j2iFile;
    protected List<String> seedStrings = new ArrayList<>();
    protected ByteBuffer feedback;
    private InputStream proxyInput;
    private OutputStream proxyOutput;

    private SingleIntentFuzzResult fuzzResult;
    private Map<Integer, Integer> responseMap;
    private CoverageGuidance ccg;
    private CodeCoverage globalCoverage;
    private int numErrors, numUniqueErrors;

    public JazzerIntentGuidance() {
        this.feedback = ByteBuffer.allocate(FEEDBACK_BUFFER_SIZE);
        this.feedback.order(ByteOrder.LITTLE_ENDIAN);
    }

    @Override
    public String getRandomIntentJson(String targetJsonStr) throws IOException, EndFuzzException {
        // check whether afl process is running or not
        if (proxyInput == null || proxyOutput == null) {
            start();
        }

        if (!hasInput())
            throw new NotActiveException("Jazzer is not ready");

        byte[] encoded = Files.readAllBytes(Paths.get("/tmp/ifuzzer/output"));

        return new String(encoded, StandardCharsets.US_ASCII);
    }

    @Override
    public boolean init(Object o) throws IOException, InterruptedException {
        fuzzResult = new SingleIntentFuzzResult();
        responseMap = new HashMap<>();
        ccg = new CoverageGuidance();
        globalCoverage = new CodeCoverage();
        numErrors = numUniqueErrors = 0;

        // mkfifo is os-dependent
        i2jFile = new File(i2j_path);
        System.out.println("GET file");
        if (!i2jFile.exists()) {
            Process p = Runtime.getRuntime().exec("mkfifo " + i2j_path);
            int exitCode = p.waitFor();
            System.out.printf("%d: $ mkfifo %s\n", exitCode, i2j_path);
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            reader.lines().forEach(System.err::println);

            i2jFile = new File(i2j_path);
        }
        i2jFile.setWritable(true, false);

        j2iFile = new File(j2i_path);
        if (!j2iFile.exists()) {
            Process p = Runtime.getRuntime().exec("mkfifo " + j2i_path);
            int exitCode = p.waitFor();
            System.out.printf("%d: $ mkfifo %s\n", exitCode, j2i_path);

            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            reader.lines().forEach(System.err::println);

            j2iFile = new File(j2i_path);
        }
        j2iFile.setWritable(true, false);

        return true;
    }

    private boolean start() throws IOException {
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

        for (int i = 0; i < seedStrings.size(); i++) {
            String seedFile = String.format("/tmp/ifuzzer/seed/input_%03d.txt", i);

            try (FileWriter fileWriter = new FileWriter(seedFile)) {
                fileWriter.write(seedStrings.get(i));
            } catch (IOException e) {
                e.printStackTrace();
            }
        }


        // 4. Open named pipes
        proxyInput = new BufferedInputStream(new FileInputStream(j2iFile));
        log.info("InputStream is opened.");
        proxyOutput = new BufferedOutputStream(new FileOutputStream(i2jFile));
        log.info("OutputStream is opened.");

        // wait client
//        try (ServerSocket serverSocket = new ServerSocket(5100)) {
//            Socket connectionSocket = serverSocket.accept();
//            /* Connect new client */
//            log.info("new client!");
//        }

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

    @Override
    public boolean stop() {
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

        if (i2jFile != null && !i2jFile.delete())
            return false;
        if (j2iFile != null && !j2iFile.delete())
            return false;

        seedStrings.clear();

        return true;
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
    public boolean feedbackResult(@Nonnull FuzzScenario parentScenario) {
        CodeCoverage cvg = parentScenario.getCodeCoverage();

        if (proxyInput == null || proxyOutput == null)
            return false;

        if (cvg == null)
            return false;

        // Reset the feedback buffer for a new run
        clearFeedbackBuffer();

        // Send the status value to Jazzer
        feedback.putInt(getStatusCode(SingleIntentFuzzResult.getStatus(parentScenario)));

        // Send trace-bits to AFL as a contiguous array
        cvg.putBitmap(feedback);

        // Send feedback to Jazzer
        try {
            proxyOutput.write(feedback.array(), 0, feedback.position());
            proxyOutput.flush();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        globalCoverage.updateCoverage(cvg);
        if (parentScenario.isError()) {
            numErrors++;
            if (ccg.isUniqueCrash(cvg) > 0)
                numUniqueErrors++;
        }

        // add results
        int code = SingleIntentGuidance.getIntentReqStatusCode(parentScenario);
        if (code > 0)
            responseMap.put(code, responseMap.getOrDefault(code, 0) + 1);
        fuzzResult.addSingleIntentResult(parentScenario);

        return true;
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
                return 1;
            case INVALID:
                return 2;
            default:
                break;
        }

        return 0;
    }
}
