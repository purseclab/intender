package edu.purdue.cs.pursec.ifuzzer.api;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.SingleIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;

import java.util.HashMap;
import java.util.Map;

public class SingleIntentFuzzResult extends FuzzResult {
    private int [][] validJsonCnt = new int[4][2];
    private Map<Integer, Integer> validResponseMap = new HashMap<>();
    private Map<Integer, Integer> invalidResponseMap = new HashMap<>();
    private Map<String, Integer> validAcceptedErrors = new HashMap<>();
    private Map<String, Integer> invalidAcceptedErrors = new HashMap<>();
    private Map<String, Integer> installedErrors = new HashMap<>();
    private Map<State, Integer> statesAfterAccepted = new HashMap<>();
    private Map<String, Integer> verifiedErrors = new HashMap<>();
    private static final String [] stepString = {"DENIED", "ACCEPTED-ONLY", "INSTALLED-ONLY", "VERIFIED"};

    public static RetStatus getStatus(FuzzScenario fuzzScenario) {
        /* 1. REST */
        if (!fuzzScenario.isAccepted()) {
            IntentInterfaceResponse response = SingleIntentGuidance.getIntentReqResponse(fuzzScenario);
            if (response == null)
                return RetStatus.INVALID;

            int code = response.getStatusCode();
            if (code >= 500)
                return RetStatus.FAILURE;
            else if (code >= 400)
                return RetStatus.INVALID;
        }

        if (!ConfigConstants.CONFIG_SET_INVALID_AS_SEMANTIC)
            return RetStatus.SUCCESS;

        /* 2. CP */
        if (!fuzzScenario.isInstalled()) {
            String errorMsg = fuzzScenario.getErrorMsg();
            if (errorMsg != null)
                return RetStatus.FAILURE;

            // no error, but not installed.
            return RetStatus.INVALID;
        }

        /* 3. DP */
        if (!fuzzScenario.isVerified())
            return RetStatus.FAILURE;

        return RetStatus.SUCCESS;
    }

    public boolean addSingleIntentResult(FuzzScenario fuzzScenario) {
        // addResult first
        super.addResult(fuzzScenario, fuzzScenario.getErrorMsg());

        int isJsonValid = 1;
        String intentStr = SingleIntentGuidance.getIntentStr(fuzzScenario);
        JsonObject intentJson = null;
        try {
            intentJson = TestUtil.fromJson(intentStr);
            // TODO: check whether it is intent form or not?
        } catch (Exception e) {
            isJsonValid = 0;
        }

        String errorMsg = fuzzScenario.getErrorMsg();
        Object intentObject = SingleIntentGuidance.getCpVerifiedIntent(fuzzScenario);

        if (!fuzzScenario.isAccepted()) {
            // 1) fail in add-intent
            validJsonCnt[0][isJsonValid]++;

            // get response while adding intent
            IntentInterfaceResponse response = SingleIntentGuidance.getIntentReqResponse(fuzzScenario);
            if (response != null) {
                int code = response.getStatusCode();
                if (isJsonValid > 0) {
                    validResponseMap.put(code, validResponseMap.getOrDefault(code, 0) + 1);
                    validAcceptedErrors.put(errorMsg, validAcceptedErrors.getOrDefault(errorMsg, 0) + 1);
                } else {
                    invalidResponseMap.put(code, invalidResponseMap.getOrDefault(code, 0) + 1);
                    invalidAcceptedErrors.put(errorMsg, invalidAcceptedErrors.getOrDefault(errorMsg, 0) + 1);
                }
            }

        } else if (!fuzzScenario.isInstalled()) {
            // 2) fail in cp-verify
            validJsonCnt[1][isJsonValid] ++;
            if (errorMsg != null) {
                installedErrors.put(errorMsg, installedErrors.getOrDefault(errorMsg, 0) + 1);
            } else if (intentObject instanceof Intent) {
                Intent intent = (Intent) intentObject;
                statesAfterAccepted.put(intent.getState(),
                        statesAfterAccepted.getOrDefault(intent.getState(), 0) + 1);
            } else {
                installedErrors.put("UNKNOWN", installedErrors.getOrDefault("UNKNOWN", 0) + 1);
            }

        } else if (!fuzzScenario.isVerified()) {
            // 3) fail in dp-verify
            validJsonCnt[2][isJsonValid] ++;
            verifiedErrors.put(errorMsg, verifiedErrors.getOrDefault(errorMsg, 0) + 1);

        } else {
            // 4) success
            validJsonCnt[3][isJsonValid] ++;
        }

        return true;
    }

    public static String getStatsHeader() {
        return "(denied, accepted-only, installed-only, verified) x (all, valid, invalid)";
    }

    public String getStatsString() {
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            if (i > 0)
                stringBuilder.append(", ");

            switch (i) {
                case 0:
                    stringBuilder.append(super.testCnt - super.acceptCnt);
                    break;
                case 1:
                    stringBuilder.append(super.acceptCnt - super.installCnt);
                    break;
                case 2:
                    stringBuilder.append(super.installCnt - super.verifyCnt);
                    break;
                case 3:
                    stringBuilder.append(super.verifyCnt);
                    break;
            }

            for (int j = 1; j >= 0; j--) {
                stringBuilder.append(", ").append(validJsonCnt[i][j]);
            }
        }
        return stringBuilder.toString();
    }

    public String getResultsString() {
        String newLineStr = System.getProperty("line.separator");
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            builder.append("----- [").append(stepString[i]).append("] -----").append(newLineStr);
            builder.append("valid cnt: ").append(validJsonCnt[i][1]).append(newLineStr);
            if (i == 0) {
                if (validResponseMap.keySet().size() > 0) {
                    builder.append("[RESPONSE CODE]").append(newLineStr);
                    for (int key : validResponseMap.keySet())
                        builder.append("  [").append(key).append("] ").append(validResponseMap.get(key)).append(newLineStr);
                }

                if (validAcceptedErrors.keySet().size() > 0) {
                    builder.append("[ERROR]").append(newLineStr);
                    for (String key : validAcceptedErrors.keySet())
                        builder.append("  ").append(key).append(": ").append(validAcceptedErrors.get(key)).append(newLineStr);
                }

            } else if (i == 1) {
                if (statesAfterAccepted.keySet().size() > 0) {
                    builder.append("[STATE]").append(newLineStr);
                    for (State state : statesAfterAccepted.keySet())
                        builder.append("  [").append(state.toString()).append("] ").append(statesAfterAccepted.get(state)).append(newLineStr);
                }

                if (installedErrors.keySet().size() > 0) {
                    builder.append("[ERROR]").append(newLineStr);
                    for (String key : installedErrors.keySet())
                        builder.append("  ").append(key).append(": ").append(installedErrors.get(key)).append(newLineStr);
                }

            } else if (i == 2) {
                for (String key : verifiedErrors.keySet())
                    builder.append("  ").append(key).append(": ").append(verifiedErrors.get(key)).append(newLineStr);
            }
            builder.append("invalid cnt: ").append(validJsonCnt[i][0]).append(newLineStr);
            if (i == 0) {
                if (invalidResponseMap.keySet().size() > 0) {
                    builder.append("[RESPONSES]").append(newLineStr);
                    for (int key : invalidResponseMap.keySet())
                        builder.append("  [").append(key).append("] ").append(invalidResponseMap.get(key)).append(newLineStr);
                }

                if (invalidAcceptedErrors.keySet().size() > 0) {
                    builder.append("[ERRORS]").append(newLineStr);
                    for (String key : invalidAcceptedErrors.keySet())
                        builder.append("  ").append(key).append(": ").append(invalidAcceptedErrors.get(key)).append(newLineStr);
                }

            }
            builder.append(newLineStr);
        }

        return builder.toString();
    }
}
