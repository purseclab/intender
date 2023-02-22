package edu.purdue.cs.pursec.ifuzzer.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.api.IntentStateCoverage;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;

import java.util.HashMap;
import java.util.Map;

public class ScenarioFuzzResult extends FuzzResult {
    // add, modify, withdraw, purge, topo-change
    private final Map<String, FuzzActionResult> resultMap = new HashMap<>();

    public boolean addScenarioResult(FuzzScenario fuzzScenario) {
        // addResult first
        super.addResult(fuzzScenario, fuzzScenario.getErrorMsg());

        for (FuzzAction fuzzAction : fuzzScenario.getActionList()) {
            FuzzActionResult fuzzActionResult = resultMap.computeIfAbsent(fuzzAction.getActionCmd(), FuzzActionResult::new);
            fuzzActionResult.addAction(fuzzAction);
        }

        IntentStateCoverage coverage = fuzzScenario.getIntentStateCoverage();
        Map <String, Integer> intentStateChangeMap = coverage.getIntentStateChanges();
        for (String actionCmd : intentStateChangeMap.keySet()) {
            FuzzActionResult fuzzActionResult = resultMap.get(actionCmd);
            if (fuzzActionResult != null)
                fuzzActionResult.addStateChangeCnt(actionCmd, intentStateChangeMap.get(actionCmd));
        }

        return true;
    }


    public String getResultsString() {
        String newLineStr = System.getProperty("line.separator");
        StringBuilder builder = new StringBuilder();
        for (FuzzActionResult fuzzActionResult : resultMap.values()) {
            builder.append(fuzzActionResult.getResultsString());
            builder.append(newLineStr);
        }

        return builder.toString();
    }
}
