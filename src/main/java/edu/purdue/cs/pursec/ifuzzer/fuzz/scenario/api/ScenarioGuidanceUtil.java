package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.api;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.IntentStore;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ScenarioGuidanceUtil {

    public static void setNewActions(FuzzScenario newScenario, List<FuzzAction> newRandomActions,
                                     IntentStore configIntentStore) {

        boolean dpVerifyIntentAtOnce = ConfigConstants.CONFIG_FUZZING_PACKET_GUIDANCE.equals("PazzPacketGuidance");

        newScenario.clearActionList();

        Set<String> toBeVerifiedIntentIdSet = new HashSet<>();
        for (FuzzAction newRandomAction : newRandomActions) {
            newScenario.addAction(newRandomAction);
            if (newRandomAction.getActionCmd().endsWith("-intent"))
                toBeVerifiedIntentIdSet.add(newRandomAction.getContent().getId());
        }

        List<FuzzAction> dpVerifyActionsForInstalled = new ArrayList<>();
        List<FuzzAction> dpVerifyActionsForOthers = new ArrayList<>();

        // Add verify action
        int i = 1;
        for (String key : toBeVerifiedIntentIdSet) {
            Intent intent = configIntentStore.getIntent(key);

            JsonObject contentJson = new JsonObject();
            contentJson.addProperty("intentId", key);

            FuzzAction verifyAction = new FuzzAction(String.format("%s-verify-%03d", newScenario.getName(), i++));
            verifyAction.setContent(new FuzzActionContent(contentJson));
            verifyAction.setActionCmd("cp-verify-intent");
            verifyAction.setSync();
            newScenario.addAction(verifyAction);

            if (!dpVerifyIntentAtOnce) {
                verifyAction = new FuzzAction(String.format("%s-verify-%03d", newScenario.getName(), i++));
                verifyAction.setContent(new FuzzActionContent(contentJson));
                verifyAction.setActionCmd("dp-verify-intent");
                verifyAction.setSync();
                if (intent != null && (State.INSTALLED.equals(intent.getState()) || intent.doNotDPTest()))
                    dpVerifyActionsForInstalled.add(verifyAction);
                else
                    dpVerifyActionsForOthers.add(verifyAction);
            }
        }

        if (dpVerifyIntentAtOnce) {
            // Create dp-verify-intent without FuzzActionContent
            FuzzAction verifyAction = new FuzzAction(String.format("%s-verify-%03d", newScenario.getName(), i));
            verifyAction.setActionCmd("dp-verify-intent");
            verifyAction.setSync();
            newScenario.addAction(verifyAction);
        } else {
            // DP-Test before deleting INSTALLED intents
            dpVerifyActionsForInstalled.forEach(newScenario::addAction);

            if (ConfigConstants.CONFIG_DP_VERIFY_WITH_DELETION &&
                    dpVerifyActionsForOthers.size() > 0) {
                i = 1;
                for (FuzzAction dpVerifyAction : dpVerifyActionsForInstalled) {
                    FuzzAction clearAction = new FuzzAction(String.format("%s-clear-%03d", newScenario.getName(), i++));
                    FuzzActionContent newContent = new FuzzActionContent(ONOSUtil.createNewContentJson());
                    newContent.setId(dpVerifyAction.getContent().getId());
                    clearAction.setContent(newContent);
                    clearAction.setActionCmd("del-intent");
                    clearAction.setSync();
                    newScenario.addAction(clearAction);
                }
            }

            // DP-Test after deleting INSTALLED intents
            dpVerifyActionsForOthers.forEach(newScenario::addAction);
        }

        newScenario.incFuzzCnt();
        newScenario.setFuzzed(true);
    }
}
