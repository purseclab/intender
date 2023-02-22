package edu.purdue.cs.pursec.ifuzzer.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;

public class FuzzResult {
    String lastErrorMsg;
    long testCnt = 0;
    long jsonErrorCnt = 0;
    long acceptCnt = 0;
    long installCnt = 0;
    long verifyCnt = 0;
    long successCnt = 0;

    public enum RetStatus {
        SUCCESS,
        FAILURE,
        INVALID
    }

    public FuzzResult() {}

    public FuzzResult(FuzzScenario fuzzScenario) {
        if (fuzzScenario.isAccepted())
            acceptCnt ++;
        if (fuzzScenario.isInstalled())
            installCnt ++;
        if (fuzzScenario.isVerified())
            verifyCnt ++;
        if (fuzzScenario.isSuccess())
            successCnt ++;
    }

    public boolean addResult(Exception e) {
        testCnt ++;
        jsonErrorCnt++;
        lastErrorMsg = e.getMessage();
        return true;
    }

    public boolean addResult(FuzzScenario fuzzScenario, String errorMsg) {
        lastErrorMsg = errorMsg;
        testCnt ++;

        /*
         * TODO: It is valid only for single-intent tests
         *      ACCEPTED    (Syntactically Correct),
         *      INSTALLED   (Topologically (Semantically) Correct),
         *      VERIFIED    (Comprehensively Correct)
         *      SUCCESS     (Correct (CP-only || (CP && DP)))
         */
        if (fuzzScenario.isAccepted())
            acceptCnt ++;
        if (fuzzScenario.isInstalled())
            installCnt ++;
        if (fuzzScenario.isVerified())
            verifyCnt ++;
        if (fuzzScenario.isSuccess())
            successCnt ++;
        if (fuzzScenario.hasSyntaxError())
            jsonErrorCnt ++;

        return true;
    }

    public String getSummary() {
        return String.format("Tests: %d, Success: %d, Syntax Error: %d, Accepted: %d, Installed: %d, Verified: %d",
                testCnt, successCnt, jsonErrorCnt, acceptCnt, installCnt, verifyCnt);
    }
}
