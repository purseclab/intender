package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl;

import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.api.FuzzScenarioGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.api.ScenarioGuidanceUtil;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.IntentStore;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionIntentContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.stream.Collectors;

public class CoverageScenarioGuidance implements FuzzScenarioGuidance {

    private static Logger log = LoggerFactory.getLogger(CoverageScenarioGuidance.class);
    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
    FuzzIntentGuidance intentGuidance;
    TopologyIntentGuidance topologyIntentGuidance;
    CodeCoverage codeCoverage = new CodeCoverage();
    List<FuzzScenario> seedScenarios = new LinkedList<>();
    private int prevHitCount = 0;
    private int curSeedIdx = -1, numCycles = 0;
    private static final IntentStore configIntentStore = IntentStore.getConfigInstance();
    Stack<TopoOperation> appliedTopoOperations = new Stack<>();
    private static final Random rand = new Random();

    public CoverageScenarioGuidance()  throws IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        Class clazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl." + ConfigConstants.CONFIG_FUZZING_INTENT_GUIDANCE);
        intentGuidance = (FuzzIntentGuidance) clazz.getDeclaredConstructor().newInstance();
        topologyIntentGuidance = new TopologyIntentGuidance();
    }

    @Override
    public void init(Object o) throws IOException, InterruptedException {
        // object will be ConfigTopoGraph
        topologyIntentGuidance.init(o);
        intentGuidance.init(o);
    }

    @Override
    public boolean stop() {
        return topologyIntentGuidance.stop();
    }

    private List<TopoOperation> getTopoOperationFromFuzzAction(List<FuzzAction> fuzzActions) throws IOException {
        List<TopoOperation> topoOperations = new ArrayList<>();

        for (FuzzAction action : fuzzActions) {
            if (action.getActionCmd().endsWith("link") ||
                    action.getActionCmd().endsWith("device") ||
                    action.getActionCmd().endsWith("host")) {
                topoOperations.add(new TopoOperation(action));
            }
        }

        return topoOperations;
    }

    private FuzzScenario getInvertScenario(FuzzScenario scenario) throws IOException {
        FuzzScenario newScenario = FuzzScenario.copy(scenario);

        newScenario.clearActionList();
        for (FuzzAction action : scenario.getActionList()) {
            if (action.getActionCmd().endsWith("link") ||
                    action.getActionCmd().endsWith("device") ||
                    action.getActionCmd().endsWith("host")) {
                TopoOperation operation = new TopoOperation(action);
                FuzzAction configAction = operation.toFuzzAction(action.getId() + "-inv");
                configAction.setSync();
                newScenario.addConfigAction(configAction);
                newScenario.addAction(operation.invert().toFuzzAction(action.getId()));
            } else {
                newScenario.addAction(FuzzAction.copy(action));
            }
        }

        return newScenario;
    }

    private boolean applyFuzzActionIntoConfig(FuzzAction fuzzAction) {
        if (fuzzAction == null)
            return false;

        if (fuzzAction.isTopoOperation()) {
            TopoOperation topoOperation = new TopoOperation(fuzzAction);
            configTopoGraph.applyTopoOperation(topoOperation);
            appliedTopoOperations.push(topoOperation);

            List<Intent> workingIntents = new ArrayList<>();
            workingIntents.addAll(configIntentStore.getIntentsByState(State.INSTALLED).values());
            workingIntents.addAll(configIntentStore.getIntentsByState(State.FAILED).values());

            int installed = 0;
            for (Intent intent : workingIntents) {
                if (TestUtil.getExpectedStateFromIntent(configTopoGraph, intent).equals(State.INSTALLED))
                    installed ++;
            }

            if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                    installed > ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                // the number of installed intents exceeds the limit
                return false;
            }

            configIntentStore.recomputeIntents(configTopoGraph, null);
            topologyIntentGuidance.resetMatrix();
            return true;

        } else if (fuzzAction.getActionCmd().equals("add-intent")) {
            String targetId = fuzzAction.getContent().getId();
            FuzzActionIntentContent actionIntentContent = (FuzzActionIntentContent)fuzzAction.getContent();
            try {
                Intent randomIntent = ONOSUtil.getIntentFromJson(actionIntentContent.getIntent());
                State randomIntentState = TestUtil.getExpectedStateFromIntent(configTopoGraph, randomIntent);
                if (randomIntentState.equals(State.INSTALLED)) {
                    if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                            configIntentStore.getIntentsByState(State.INSTALLED).size() >=
                                    ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                        // do not generate two installed intent at the same time
                        log.debug("cannot add intent due to limit number of installed intents");
                        return false;
                    }
                }
                randomIntent.setState(randomIntentState);
                configIntentStore.addIntent(targetId, randomIntent);

            } catch (Exception ignored) {}
            return true;

        } else if (fuzzAction.getActionCmd().equals("mod-intent")) {
            String targetId = fuzzAction.getContent().getId();
            Intent targetIntent = configIntentStore.getIntent(targetId);
            if (targetIntent == null) {
                log.error("mod-intent cannot find intent by id {}", targetId);
                return false;
            }

            FuzzActionIntentContent actionIntentContent = (FuzzActionIntentContent)fuzzAction.getContent();
            try {
                Intent randomIntent = ONOSUtil.getIntentFromJson(actionIntentContent.getIntent());
                State randomIntentState = TestUtil.getExpectedStateFromIntent(configTopoGraph, randomIntent);
                if (!targetIntent.getState().equals(State.INSTALLED) &&
                        randomIntentState.equals(State.INSTALLED)) {
                    if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                            configIntentStore.getIntentsByState(State.INSTALLED).size() >=
                                    ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                        // do not generate two installed intent at the same time
                        log.debug("cannot mod intent due to limit number of installed intents");
                        return false;
                    }
                }
                randomIntent.setState(randomIntentState);
                configIntentStore.modIntent(targetId, randomIntent);

            } catch (Exception ignored) {}
            return true;

        } else if (fuzzAction.getActionCmd().equals("withdraw-intent")) {
            String targetId = fuzzAction.getContent().getId();
            Intent targetIntent = configIntentStore.getIntent(targetId);
            if (targetIntent != null && !targetIntent.getState().equals(State.REMOVED)) {
                targetIntent.setState(State.WITHDRAWN);
            }
            return true;

        } else if (fuzzAction.getActionCmd().equals("purge-intent")) {
            String targetId = fuzzAction.getContent().getId();
            Intent targetIntent = configIntentStore.getIntent(targetId);
            if (targetIntent != null && targetIntent.getState().equals(State.WITHDRAWN)) {
                targetIntent.setState(State.REMOVED);
            }
            return true;
        }

        /* unknown action */
        log.error("unknown command: {}", fuzzAction.getActionCmd());
        return false;
    }

    @Override
    public FuzzScenario getRandomScenario(FuzzScenario scenario)
            throws IOException, JsonSyntaxException, EndFuzzException {

        // store given scenario into seed
        if (codeCoverage != null) {
            int curHitCount = codeCoverage.getBranchHitCount();
            if (prevHitCount < curHitCount) {
                // Guidance finds new coverage path
                seedScenarios.add(scenario);

                log.info("## Add new matrix {} -> {} into seeds: {} | cycle {} ##",
                        prevHitCount, curHitCount,
                        seedScenarios.size(), numCycles);
                prevHitCount = curHitCount;
            }
        }

        // Run once again
        if (seedScenarios.size() == 0)
            return FuzzScenario.copy(scenario);

        curSeedIdx = (curSeedIdx + 1) % seedScenarios.size();
        if (curSeedIdx == 0)
            numCycles++;
        FuzzScenario seedScenario = seedScenarios.get(curSeedIdx);
        FuzzScenario newScenario = FuzzScenario.copy(seedScenario);
        newScenario.setFuzzCnt(scenario.getFuzzCnt());

        // TODO: implement mutation-based fuzzing: move action to configAction
        newScenario.clearConfigActions();
        configIntentStore.clear();

//        for (FuzzAction configAction : newScenario.getConfigActions()) {
//            if (configAction.isTopoOperation()) {
//                configTopoGraph.applyTopoOperation(new TopoOperation(configAction));
//            } else if (configAction.getActionCmd().equals("add-intent")) {
//                configIntentStore.addIntent(configAction.getContent().getContent());
//            }
//        }

        List<FuzzAction> prevActions = new ArrayList<>();
        if (ConfigConstants.CONFIG_DP_VERIFY_WITH_DELETION) {
            for (FuzzAction action : newScenario.getActionList()) {
                if (action.getActionCmd().contains("verify-intent"))
                    break;
                prevActions.add(action);
            }
        } else {
            prevActions = newScenario.getActionList().stream()
                    .filter(k -> !k.getActionCmd().contains("verify-intent"))
                    .collect(Collectors.toList());
        }

        List<FuzzAction> newRandomActions = new ArrayList<>();
        TopoOperation prevTopoOperation = null;
        int numRemoval = rand.nextInt(2);       // [0, 1]
        for (int i = 0; i < prevActions.size() - numRemoval; i++) {
            FuzzAction prevAction = prevActions.get(i);
//            prevAction.setId(String.format("%s-rand-%03d-%03d",
//                    newScenario.getName(),
//                    newScenario.getFuzzCnt() + 1,
//                    ++actionNum));
            applyFuzzActionIntoConfig(prevAction);      // what if scenario violates config?
            newRandomActions.add(prevAction);
            if (prevAction.isTopoOperation()) {
                prevTopoOperation = new TopoOperation(prevAction);
            } else {
                prevTopoOperation = null;
            }
        }
        topologyIntentGuidance.resetMatrix();

        int actionNum = 0;
        int numActions = rand.nextInt(3) + 1;   // [1, 3]
        for (int i = 0; i < numActions; i++) {
            // purely generate random action.
            String actionId = String.format("%s-rand-%03d-%03d", newScenario.getName(),
                    newScenario.getFuzzCnt() + 1, ++actionNum);
            FuzzAction newAction = new FuzzAction(actionId);

            String randomIntentStr;
            FuzzActionContent newContent;
            Intent targetIntent;
            String targetId;
            while (true) {
                int caseNum = rand.nextInt(5);

                // If there was no intent action, add-intent
                if (i == numActions - 1 && configIntentStore.getAllIntents().size() == 0)
                    caseNum = 0;

                switch (caseNum) {
                    case 0:
                        // add-intent
                        randomIntentStr = intentGuidance.getRandomIntentJson(null);
                        newContent = new FuzzActionIntentContent(ONOSUtil.createNewContentJson(), randomIntentStr);
                        newContent.setNewId();
                        try {
                            Intent randomIntent = ONOSUtil.getIntentFromJson(randomIntentStr);
                            State randomIntentState = TestUtil.getExpectedStateFromIntent(configTopoGraph, randomIntent);
                            if (randomIntentState.equals(State.INSTALLED)) {
                                if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                                        configIntentStore.getIntentsByState(State.INSTALLED).size() >=
                                                ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                                    // do not generate two installed intent at the same time
                                    continue;
                                }
                            }
                            randomIntent.setState(randomIntentState);
                            configIntentStore.addIntent(newContent.getId(), randomIntent);

                        } catch (Exception ignored) {}

                        newAction.setContent(newContent);
                        newAction.setActionCmd("add-intent");
                        newAction.setSync();
                        break;

                    case 1:
                        // mod-intent
                        if (configIntentStore.isEmpty())
                            continue;

                        targetId = configIntentStore.getKeyOfRandomIntent(rand, true);
                        if (targetId == null)
                            continue;
                        targetIntent = configIntentStore.getIntent(targetId);

                        randomIntentStr = intentGuidance.getRandomIntentJson(null);
                        newContent = new FuzzActionIntentContent(ONOSUtil.createNewContentJson(), randomIntentStr);
                        newContent.setId(targetId);
                        try {
                            Intent randomIntent = ONOSUtil.getIntentFromJson(randomIntentStr);
                            State randomIntentState = TestUtil.getExpectedStateFromIntent(configTopoGraph, randomIntent);
                            if (!targetIntent.getState().equals(State.INSTALLED) &&
                                    randomIntentState.equals(State.INSTALLED)) {
                                if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                                        configIntentStore.getIntentsByState(State.INSTALLED).size() >=
                                                ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                                    // do not generate two installed intent at the same time
                                    continue;
                                }
                            }
                            randomIntent.setState(randomIntentState);
                            configIntentStore.modIntent(targetId, randomIntent);

                        } catch (Exception ignored) {}

                        newAction.setContent(newContent);
                        newAction.setActionCmd("mod-intent");
                        newAction.setSync();
                        break;

                    case 2:
                        // withdraw-intent
                        if (configIntentStore.isEmpty())
                            continue;

                        targetId = configIntentStore.getKeyOfRandomIntent(rand, false);
                        if (targetId == null)
                            continue;
                        targetIntent = configIntentStore.getIntent(targetId);
                        if (!targetIntent.getState().equals(State.REMOVED)) {
                            targetIntent.setState(State.WITHDRAWN);
                        }

                        newContent = new FuzzActionContent(ONOSUtil.createNewContentJson());
                        newContent.setId(targetId);
                        newAction.setContent(newContent);
                        newAction.setActionCmd("withdraw-intent");
                        newAction.setSync();

                        break;

                    case 3:
                        // purge-intent
                        if (configIntentStore.isEmpty())
                            continue;

                        targetId = configIntentStore.getKeyOfRandomIntent(rand, false);
                        if (targetId == null)
                            continue;
                        targetIntent = configIntentStore.getIntent(targetId);
                        if (targetIntent.getState().equals(State.WITHDRAWN)) {
                            targetIntent.setState(State.REMOVED);
                        }

                        newContent = new FuzzActionContent(ONOSUtil.createNewContentJson());
                        newContent.setId(targetId);
                        newAction.setContent(newContent);
                        newAction.setActionCmd("purge-intent");
                        newAction.setSync();

                        break;

                    case 4:
                        // topology operation
                        // Get random operations from current matrix
                        List<Intent> workingIntents = new ArrayList<>();
                        workingIntents.addAll(configIntentStore.getIntentsByState(State.INSTALLED).values());
                        workingIntents.addAll(configIntentStore.getIntentsByState(State.FAILED).values());

                        TopoOperation topoOperation;
                        while (true) {
                            topoOperation = topologyIntentGuidance.getRandomTopoOperationFromCurMatrix(prevTopoOperation);
                            configTopoGraph.applyTopoOperation(topoOperation);

                            int installed = 0;
                            for (Intent intent : workingIntents) {
                                if (TestUtil.getExpectedStateFromIntent(configTopoGraph, intent).equals(State.INSTALLED))
                                    installed ++;
                            }

                            if (ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT > 0 &&
                                    installed > ConfigConstants.CONFIG_FUZZING_MAX_INSTALLED_INTENT) {
                                // the number of installed intents exceeds the limit
                                configTopoGraph.applyTopoOperation(topoOperation.invert());
                                continue;
                            }

                            // apply topo-operation
                            configIntentStore.recomputeIntents(configTopoGraph, null);
                            break;
                        }
                        prevTopoOperation = topoOperation;
                        appliedTopoOperations.push(topoOperation);
                        topologyIntentGuidance.resetMatrix();
                        newAction = topoOperation.toFuzzAction(actionId);
                        newAction.setSync();
                        break;

                    default:
                        break;
                }

                // successfully generate operation
                break;
            }

            newRandomActions.add(newAction);

            if (!newAction.isTopoOperation())
                prevTopoOperation = null;
        }

        // Move newRandomActions to newScenario
        ScenarioGuidanceUtil.setNewActions(newScenario, newRandomActions, configIntentStore);

        // revert configTopoGraph
        while (!appliedTopoOperations.isEmpty()) {
            configTopoGraph.applyTopoOperation(appliedTopoOperations.pop().invert());
        }

        return newScenario;
    }

    @Override
    public boolean feedbackResult(@Nonnull FuzzScenario fuzzScenario) {

        codeCoverage.updateCoverage(fuzzScenario.getCodeCoverage());

        intentGuidance.feedbackResult(fuzzScenario);
        topologyIntentGuidance.feedbackResult(fuzzScenario);

        return true;
    }

    private FuzzAction getRandomTopoAction(FuzzAction configAction) {
        if (configAction.getActionCmd().endsWith("link") ||
                configAction.getActionCmd().endsWith("device") ||
                configAction.getActionCmd().endsWith("host")) {
            FuzzAction newAction = topologyIntentGuidance.getRandomTopoOperation().toFuzzAction(configAction.getId());
            newAction.setSync();
            return newAction;
        }

        return FuzzAction.copy(configAction);
    }

    @Override
    public FuzzAction getRandomAction(FuzzAction action) throws IOException, EndFuzzException {
        // copy first
        FuzzAction newAction = FuzzAction.copy(action);

        FuzzActionContent seedContent = action.getSeedContent();
        if (seedContent instanceof FuzzActionIntentContent) {

            // copy content from the seed
            FuzzActionIntentContent newContent = (FuzzActionIntentContent) seedContent.deepCopy();

            // get intent from the content
            String intent = newContent.getIntent();

            // generate random withdraw request..!
            String randomIntent = intentGuidance.getRandomIntentJson(intent);

            // set intent
            newContent.setIntent(randomIntent);

            // update content
            newAction.setContent(newContent);
        }

        return newAction;
    }

    @Override
    public boolean doesRequireLogging(FuzzScenario scenario) {
        return topologyIntentGuidance.doesRequireLogging(scenario);
    }

    @Override
    public String getStatsHeader() {
        return CodeCoverage.getStatsHeader();
    }

    @Override
    public String getStatsString() {
        return codeCoverage.getStatsString();
    }

    @Override
    public String getResultsString() {
        return null;
    }

    @Override
    public void addSeeds(Collection<FuzzScenario> fuzzScenarios) {
        // TODO
    }
}
