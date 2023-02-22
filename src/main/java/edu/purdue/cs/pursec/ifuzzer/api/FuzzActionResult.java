package edu.purdue.cs.pursec.ifuzzer.api;

import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;

import java.util.HashMap;
import java.util.Map;

public class FuzzActionResult {
    private final String actionId;      // checker
    private int successCnt = 0, errorCnt = 0, stateChangeCnt = 0;
    private final Map<State, Integer> intentStateMap = new HashMap<>();
    private final Map<String, Integer> errorMap = new HashMap<>();
    private long sumDurationMillis = 0;

    public FuzzActionResult(String actionId) {
        this.actionId = actionId;
    }

    public boolean addAction(FuzzAction fuzzAction) {
        if (!fuzzAction.getActionCmd().equals(actionId))
            return false;

        if (fuzzAction.getRetObject() instanceof Intent) {
            Intent intent = (Intent) fuzzAction.getRetObject();
            intentStateMap.put(intent.getState(),
                    intentStateMap.getOrDefault(intent.getState(), 0) + 1);
        }

        if (fuzzAction.isError()) {
            errorMap.put(fuzzAction.getErrorMsg(),
                    errorMap.getOrDefault(fuzzAction.getErrorMsg(), 0) + 1);
            errorCnt ++;
        } else {
            successCnt ++;
        }

        sumDurationMillis += fuzzAction.getDurationMillis();

        return true;
    }

    public boolean addStateChangeCnt(String actionId, int stateChangeCnt) {
        if (!this.actionId.equals(actionId))
            return false;

        this.stateChangeCnt += stateChangeCnt;
        return true;
    }

    public String getResultsString() {
        if (errorCnt + successCnt == 0)
            return null;

        String newLineStr = System.getProperty("line.separator");
        StringBuilder builder = new StringBuilder();

        builder.append("----- [").append(actionId.toUpperCase()).append("] -----").append(newLineStr);
        builder.append("duration (ms): ").append(sumDurationMillis).append(newLineStr);

        if (successCnt > 0) {
            builder.append("success cnt: ").append(successCnt).append(newLineStr);
        }

        if (stateChangeCnt > 0) {
            builder.append("state-change cnt: ").append(stateChangeCnt).append(newLineStr);
        }

        if (intentStateMap.keySet().size() > 0) {
            builder.append("[STATE]").append(newLineStr);
            for (State state : intentStateMap.keySet())
                builder.append("  [").append(state.toString()).append("] ")
                        .append(intentStateMap.get(state)).append(newLineStr);
        }

        if (errorCnt > 0) {
            builder.append("error cnt: ").append(errorCnt).append(newLineStr);

            if (errorMap.keySet().size() > 0) {
                builder.append("[ERROR]").append(newLineStr);
                for (String key : errorMap.keySet())
                    builder.append("  ").append(key).append(": ")
                            .append(errorMap.get(key)).append(newLineStr);
            }
        }

        return builder.toString();
    }
}
