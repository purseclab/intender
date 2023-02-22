package edu.purdue.cs.pursec.ifuzzer.scenario.impl;

import com.google.gson.*;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.cli.FuzzCommand;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.GuidanceException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.IntentStateCoverage;
import edu.purdue.cs.pursec.ifuzzer.store.api.StoreElem;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoHost;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.ConfigTopo;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoMatrix;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import org.jacoco.core.tools.ExecFileLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;

import static edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore.scenarioGuidance;

public class FuzzScenario implements StoreElem, Runnable {
    private static final Logger log = LoggerFactory.getLogger(FuzzScenario.class);
    private int fuzzCnt;
    boolean isFuzzed = false;
    private String name;
    List<FuzzAction> actionList = new ArrayList<>();
    List<FuzzAction> failedActions = new ArrayList<>();
    List<FuzzAction> initActions = new ArrayList<>();
    List<FuzzAction> configActions = new ArrayList<>();
    List<TopoOperation> appliedTopoOperations = new ArrayList<>();
    List<TopoOperation> revertedTopoOperations = new ArrayList<>();
    int currentIdx = 0;
    ConfigTopo configTopo;
    private boolean checked;
    Thread coverageBgWorker = null;

    // Result-related data
    CodeCoverage codeCoverage = new CodeCoverage();
    IntentStateCoverage intentStateCoverage = new IntentStateCoverage();
    private String errorMsg;
    boolean isInit;
    boolean isUniqueError;
    private boolean isSingleIntentDpError;      // ONOS-2 BUG

    public FuzzScenario(JsonObject jsonObject) throws JsonParseException {
        if (!jsonObject.has("name"))
            throw new JsonParseException("name field missing");
        name = jsonObject.get("name").getAsString();
        fuzzCnt = 0;
        isInit = true;

        // TODO: Parse JSON in execution of Scenario, instead of constructor
        if (!jsonObject.has("actions"))
            throw new JsonParseException("actions field missing");
        JsonArray actionArr = jsonObject.get("actions").getAsJsonArray();
        int idx = 0;
        for (JsonElement action : actionArr) {
            actionList.add(new FuzzAction(String.format("%s-action-%03d", name, idx++), action.getAsJsonObject()));
        }

        boolean loadHost = false;
        // TODO: Check topology and build initActions in execution of Scenario, instead of contructor
        if (jsonObject.has("topology")) {
            JsonObject topoJson = jsonObject.get("topology").getAsJsonObject();
            if (topoJson.has("configTopo")) {
                configTopo = new ConfigTopo();
                configTopo.setConfig(topoJson.get("configTopo").getAsJsonObject());
                checked = false;
            }

            JsonObject initActionJson = new JsonObject();
            initActionJson.addProperty("action", "create-topo");
            initActionJson.add("content", topoJson);

            FuzzAction createTopoAction = new FuzzAction(String.format("%s-init", name), initActionJson);
            createTopoAction.setSync();

            initActions.add(createTopoAction);
            loadHost = true;
        }

        if (jsonObject.has("topoOperations")) {
            idx = 1;
            JsonArray topoOperationJsonArr = jsonObject.get("topoOperations").getAsJsonArray();

            for (JsonElement topoOperationJsonElem : topoOperationJsonArr) {
                JsonObject topoOperationJson = topoOperationJsonElem.getAsJsonObject();
                TopoOperation topoOperation = new TopoOperation(topoOperationJson);

                if (topoOperation.getElem() instanceof TopoHost)
                    loadHost = true;

                appliedTopoOperations.add(topoOperation);
                initActions.add(new FuzzAction(String.format("%s-init-%03d", name, idx++), topoOperationJson));
            }
        }

        if (loadHost)
            initActions.add(FuzzAction.loadHostAction);

        if (jsonObject.has("configActions")) {
            idx = 1;
            JsonArray configActionsJsonArr = jsonObject.get("configActions").getAsJsonArray();

            for (JsonElement configActionsJsonElem : configActionsJsonArr) {
                JsonObject configActionJson = configActionsJsonElem.getAsJsonObject();
                FuzzAction configFuzzAction = new FuzzAction(String.format("%s-config-%03d", name, idx++), configActionJson);
                configFuzzAction.setSync();
//                if (initFuzzAction.getActionCmd().equals("add-host"))
//                    loadHost = true;
                configActions.add(configFuzzAction);
            }
        }

        for (FuzzAction initAction : initActions) {
            initAction.setInitAction();
        }
    }

    private FuzzScenario(FuzzScenario scenario) {
        name = scenario.getName();
        fuzzCnt = scenario.getFuzzCnt();
        configTopo = scenario.getConfigTopo();
        checked = scenario.checked;
        appliedTopoOperations = scenario.appliedTopoOperations;
        isInit = false;
    }

    private static final int RANDOM_ADD_INTENT      = 0;
    private static final int RANDOM_DEL_INTENT      = 1;
    private static final int RANDOM_MOD_INTENT      = 2;
    private static final int RANDOM_MUTATE_TOPO     = 3;
    private static final int RANDOM_FUZZ_OPER_MAX   = 2;

    private static final int INTENT_SYNC_BIT        = 1;
    private static final int INTENT_REMOVED_BIT     = 1 << 1;

    public static FuzzScenario fuzz(FuzzScenario scenario)
            throws IOException, JsonSyntaxException, EndFuzzException, GuidanceException {
        return scenarioGuidance.getRandomScenario(scenario);
    }

    public static FuzzScenario copy(FuzzScenario scenario) {
        FuzzScenario newScenario = new FuzzScenario(scenario);

        for (FuzzAction configAction : scenario.getConfigActions()) {
            newScenario.addConfigAction(FuzzAction.copy(configAction));
        }

        for (FuzzAction action : scenario.getActionList()) {
            newScenario.addAction(FuzzAction.copy(action));
        }

        return newScenario;
    }

    public static FuzzScenario deepcopy(FuzzScenario scenario) {
        FuzzScenario newScenario = new FuzzScenario(scenario);

        for (FuzzAction configAction : scenario.getConfigActions()) {
            newScenario.addConfigAction(FuzzAction.deepcopy(configAction));
        }

        for (FuzzAction action : scenario.getActionList()) {
            newScenario.addAction(FuzzAction.deepcopy(action));
        }

        return newScenario;
    }

    public String getName() {
        return name;
    }

    public void setFuzzed(boolean fuzzed) {
        isFuzzed = fuzzed;
    }

    public boolean isFuzzed() {
        return this.isFuzzed;
    }

    public void setFuzzCnt(int fuzzCnt) {
        this.fuzzCnt = fuzzCnt;
    }

    public int getFuzzCnt() {
        return fuzzCnt;
    }

    public void incFuzzCnt() {
        this.fuzzCnt ++;
    }

    public boolean isDone() {
        return currentIdx >= actionList.size();
    }

    public FuzzAction getNextAction() {
        if (this.isDone())
            return null;

        return (actionList.get(currentIdx++));
    }

    public List<FuzzAction> getInitActions() {
        return initActions;
    }

    public boolean addInitAction(FuzzAction initAction) {
        return initActions.add(initAction);
    }

    public List<FuzzAction> getConfigActions() {
        return configActions;
    }

    public boolean addConfigAction(FuzzAction configAction) {
        return configActions.add(configAction);
    }

    public boolean isError() {
        if (errorMsg != null)
            return true;

        for (FuzzAction action : actionList) {
            if (action.isError())
                return true;
        }

        return false;
    }

    public void setError(String errorMsg) {
        this.errorMsg = errorMsg;
    }

    public String getErrorMsg() {
        if (this.errorMsg != null)
            return errorMsg;

        String msg = null;
        for (FuzzAction action : actionList) {
            if (action.isError()) {
                msg = action.getId() + ":" + action.errorMsg;
                if (!action.isSingleIntentDpError)
                    return msg;
            }
        }

        return msg;
    }

    public boolean isSuccess() {
        if (errorMsg != null)
            return false;

        for (FuzzAction action : actionList) {
            if (!action.isSuccess())
                return false;
        }

        return true;
    }

    public boolean hasSyntaxError() {
        for (FuzzAction action : actionList) {
            if (!action.hasSyntaxError())
                return false;
        }

        return true;
    }

    public boolean doesRequireLogging() {
        for (FuzzAction action : actionList) {
            if (action.doesRequireLogging())
                return true;
        }

        return false;
    }

    public boolean stopFuzz() {
        for (FuzzAction action : actionList) {
            if (action.stopFuzz())
                return true;
        }

        return false;
    }

    public boolean isAccepted() {
        for (FuzzAction action : actionList) {
            // TODO: what if there are multiple add-intent actions?
            if (action.isAccepted())
                return true;
        }

        return false;
    }

    public boolean isInstalled() {
        for (FuzzAction action : actionList) {
            // TODO: what if there are multiple add-intent actions?
            if (action.isInstalled())
                return true;
        }

        return false;
    }

    public boolean isVerified() {
        for (FuzzAction action : actionList) {
            // TODO: what if there are multiple add-intent actions?
            if (action.isVerified())
                return true;
        }

        return false;
    }

    public void addAction(FuzzAction action) {
        actionList.add(action);
    }
    public List<FuzzAction> getActionList() {
        return actionList;
    }
    public void clearActionList() {
        actionList.clear();
    }
//    public void clearInitActionList() {
//        initActions.clear();
//    }
    public void clearConfigActions() {
        configActions.clear();
    }

    public ConfigTopo getConfigTopo() {
        return configTopo;
    }

    public void setConfigTopo(ConfigTopo configTopo) {
        this.configTopo = configTopo;
    }

    public boolean requireConfigTopo() {
        if (configTopo == null)
            return false;

        if (checked)
            return false;

        return true;
    }

    public CodeCoverage getCodeCoverage() {
        return codeCoverage;
    }

    public void applyCodeCoverage(ExecFileLoader loader) {
        if (coverageBgWorker != null && coverageBgWorker.isAlive()) {
            coverageBgWorker.interrupt();
        }

        this.codeCoverage.applyLoader(loader);
    }

    public void startCoverageBgWorker() {
        coverageBgWorker = new Thread(this);
        coverageBgWorker.start();
    }

    @Override
    public void run() {
        while (!Thread.interrupted()) {
            try {
                ExecFileLoader loader = ONOSUtil.dumpCoverage(false);
                this.codeCoverage.applyLoader(loader);

                if (FuzzCommand.statOut != null) {
                    FuzzCommand.statOut.println(this.codeCoverage.getStatsString());
                    FuzzCommand.statOut.flush();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            try {
                Thread.sleep(1000 * ConfigConstants.CONFIG_MEASURE_STAT_INTERVAL);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public IntentStateCoverage getIntentStateCoverage() {
        return this.intentStateCoverage;
    }
    public void applyIntentStateCoverage(FuzzAction action) throws UnsupportedOperationException {
        applyIntentStateCoverage(action, null);
    }

    public void applyIntentStateCoverage(FuzzAction action, Object retObject) throws UnsupportedOperationException {
        this.intentStateCoverage.applyAction(action, retObject);
    }

    public void logAction(FuzzAction action) {
        this.intentStateCoverage.logAction(action);
    }

    public boolean isInit() {
        return isInit;
    }

    public boolean isUniqueError() {
        return isUniqueError;
    }

    public void setUniqueError() {
        isUniqueError = true;
    }

    public boolean isSingleIntentDpError() {
        return isSingleIntentDpError;
    }

    public void setSingleIntentDpError(boolean singleIntentDpError) {
        isSingleIntentDpError = singleIntentDpError;
    }

    public boolean addTopoOperation(TopoOperation topoOperation) {
        return this.appliedTopoOperations.add(topoOperation);
    }

    public boolean updateTopoOperations(TopoMatrix topoMatrix) {
        this.appliedTopoOperations.clear();
        return this.appliedTopoOperations.addAll(topoMatrix.getAppliedTopoOperations());
    }

    public boolean updateTopoOperation(TopoOperation oldOperation, TopoOperation newOperation) {
        int idx = appliedTopoOperations.indexOf(oldOperation);
        if (idx < 0)
            return false;

        appliedTopoOperations.set(idx, newOperation);
        return true;
    }

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    public String getResult() {
        return String.format("[%s:%d] %s", this.getName(), this.getFuzzCnt(),
                this.isSuccess() ? "SUCCESS" :
                this.isError() ? "ERROR: " + this.getErrorMsg() :
                "processing ...");
    }

    public JsonObject toJsonObject() throws IOException {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("name", this.name);

        if (this.configTopo != null) {
            // TODO: log controller setting
            JsonObject configTopoJson = new JsonObject();
            configTopoJson.add("configTopo", this.configTopo.getConfigJson());
            jsonObject.add("topology", configTopoJson);

            if (this.appliedTopoOperations.size() > 0) {
                JsonArray topoOperationJsonArr = new JsonArray();

                for (TopoOperation topoOperation : this.appliedTopoOperations) {
                    topoOperationJsonArr.add(topoOperation.toFuzzActionJson());
                }

                jsonObject.add("topoOperations", topoOperationJsonArr);
            }
        }

        JsonArray configActionJsonArray = new JsonArray();
        for (FuzzAction configAction : getConfigActions()) {
            configActionJsonArray.add(configAction.toJsonObject());
        }
        jsonObject.add("configActions", configActionJsonArray);

        JsonArray actionJsonArray = new JsonArray();
        for (FuzzAction action : getActionList()) {
            actionJsonArray.add(action.toJsonObject());
        }
        jsonObject.add("actions", actionJsonArray);

        JsonObject resultObject = new JsonObject();
        resultObject.addProperty("isAccepted", isAccepted());
        resultObject.addProperty("isInstalled", isInstalled());
        resultObject.addProperty("isVerified", isVerified());
        resultObject.addProperty("isSuccess", isSuccess());
        jsonObject.add("result", resultObject);

        String errorMsg = this.getErrorMsg();
        if (errorMsg != null)
            jsonObject.addProperty("errorMsg", errorMsg);

        return jsonObject;
    }
}
