package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl;

import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.ScenarioFuzzResult;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CoverageGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.IntentStateCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.api.FuzzScenarioGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.api.IntentStateGuidanceConfigs;
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
import java.nio.ByteBuffer;
import java.util.*;

public class IntentStateGuidance implements FuzzScenarioGuidance {
    private static final int ADD_INTENT_OPERATION = 0;
    private static final int MOD_INTENT_OPERATION = 1;
    private static final int WITHDRAW_INTENT_OPERATION = 2;
    private static final int PURGE_INTENT_OPERATION = 3;
    private static final int CHANGE_TOPO_OPERATION = 4;

    private static final Random rand = new Random();
    private static Logger log = LoggerFactory.getLogger(IntentStateGuidance.class);
    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
    private static final IntentStore configIntentStore = IntentStore.getConfigInstance();
    FuzzIntentGuidance intentGuidance;
    TopologyIntentGuidance topologyIntentGuidance;
    CodeCoverage codeCoverage;
    List<FuzzScenario> seedScenarios;
    private int prevStateHistoryCnt, prevStateChangeCnt;
    private int curSeedIdx, numCycles;
    private int numErrors, numUniqueErrors;
    Stack<TopoOperation> appliedTopoOperations;
    Map<Integer, Set<ByteBuffer>> stateCoverage;
    private boolean hasSingleIntentDpError;
    IntentStateCoverage globalIntentStateCoverage;
    CoverageGuidance ccg;

    /* stats */
    private ScenarioFuzzResult fuzzResult;
    private Map<Integer, Integer> responseMap;

    public IntentStateGuidance()  throws IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        Class clazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl." + ConfigConstants.CONFIG_FUZZING_INTENT_GUIDANCE);
        intentGuidance = (FuzzIntentGuidance) clazz.getDeclaredConstructor().newInstance();
        topologyIntentGuidance = new TopologyIntentGuidance();
    }

    @Override
    public void init(Object o) throws IOException, InterruptedException {
        fuzzResult = new ScenarioFuzzResult();
        responseMap = new HashMap<>();
        ccg = new CoverageGuidance();
        globalIntentStateCoverage = new IntentStateCoverage();
        seedScenarios = new LinkedList<>();
        codeCoverage = new CodeCoverage();
        appliedTopoOperations = new Stack<>();
        stateCoverage = new HashMap<>();
        curSeedIdx = -1;
        numCycles = numErrors = numUniqueErrors = prevStateHistoryCnt = prevStateChangeCnt = 0;

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

    private int getRandOperationFromIntentId(String intentId, FuzzAction prevAction) {
        // No intent
        if (intentId == null)
            return ADD_INTENT_OPERATION;

        Intent intent = configIntentStore.getIntent(intentId);
        if (intent == null)
            return ADD_INTENT_OPERATION;

        // If prevAction was device-related action, give one more chance
        if (prevAction != null && prevAction.getActionCmd().endsWith("-device")) {
            return CHANGE_TOPO_OPERATION;
        }

        // Expected, Expected / Penalty, Number of intent / Overhead
        // => Expected * Overhead * Penalty, Expected * Overhead, Number of intent * Penalty
        // e.g.) 8, 8, 4, 4, 6 (total: 30)
        // => [0, 7][8, 15][16, 19][20, 23][24, 29]
        int[] prob = new int[5];
        prob[ADD_INTENT_OPERATION] = IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY *
                IntentStateGuidanceConfigs.CONFIG_TOPO_CHANGE_OPERATION_OVERHEAD *
                IntentStateGuidanceConfigs.CONFIG_WEIGHT_ADD_INTENT;                    // fixed
        prob[MOD_INTENT_OPERATION] = IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY *
                IntentStateGuidanceConfigs.CONFIG_TOPO_CHANGE_OPERATION_OVERHEAD;       // fixed
        prob[WITHDRAW_INTENT_OPERATION] = (State.WITHDRAWN.equals(intent.getState()) ? 1 : IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY) *
                IntentStateGuidanceConfigs.CONFIG_TOPO_CHANGE_OPERATION_OVERHEAD;       // dynamic
        prob[PURGE_INTENT_OPERATION] = ((State.FAILED.equals(intent.getState()) || State.WITHDRAWN.equals(intent.getState())) ?
                IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY : 1) *
                IntentStateGuidanceConfigs.CONFIG_TOPO_CHANGE_OPERATION_OVERHEAD;       // dynamic
        prob[CHANGE_TOPO_OPERATION] = IntentStateGuidanceConfigs.CONFIG_EXCEPTIONAL_OPERATION_PENALTY *
                (IntentStateGuidanceConfigs.CONFIG_IS_TOPO_CHANGE_RELATIVE_TO_INTENTS ?
                        configIntentStore.getAllAliveIntents().size() : 1);

        int sum = 0;
        for (int i = 0; i < 5; i++) {
            sum += prob[i];
        }

        int target = rand.nextInt(sum);
        for (int i = 0; i < 5; i++) {
            if (target < prob[i])
                return i;
            target -= prob[i];
        }

        // unreachable...
        log.error("!!! fail to get operation !!!");
        return -1;
    }

    private int getNumAppendOperation(int numPrevActions, int numRemoval) {
        /*
         * If numPrevActions is too large comparing to seed, slowly append operations.
         * Eq: seed = (x > 5) ^ (numPrevActions - 1), since first action should be add-intent
         *     Also, even if the same operation, it can generate different state transitions.
         *     To simplify, we use (seed >> numPrevActions)
         * e.g) 25 seeds, prevActions = 3, should generate. (25 >> 3) == 3
         *      125 seeds, prevActions = 10, should decrease. (125 >> 10) == 0
         *      625 seeds, prevActions = 8, should generate. (625 >> 8) == 2
         * v (>= 1): velocity of append operations, which decides whether it replaces or appends.
         *    (seed >> (prevActions - v) == 0)
         *    If v is high, it appends more and more.
         *    Otherwise, it appends slowly.
         * e.g.) v = 10, 125 seeds
         *       prevActions <= 10, it always generates more operations.
         *       prevActions = 20, decrease.
         */
        int v = IntentStateGuidanceConfigs.CONFIG_VELOCITY_OF_APPEND;
        if ((seedScenarios.size() >> Integer.max(0, numPrevActions - v)) > 0) {
            // 1) append more
            return (1 + rand.nextInt(Integer.max(1,
                    IntentStateGuidanceConfigs.CONFIG_MAX_NUM_APPEND_OPERATIONS)));
        } else if (numRemoval == 0) {
            // 2) append one operation at least
            return 1;
        } else {
            // 3) append or not
            return rand.nextInt(1);
        }
    }

    @Override
    public FuzzScenario getRandomScenario(FuzzScenario scenario)
            throws IOException, JsonSyntaxException, EndFuzzException {
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
        boolean truncated = false;
        for (FuzzAction action : newScenario.getActionList()) {
            if (action.getActionCmd().contains("verify-intent")) {
                if (ConfigConstants.CONFIG_DP_VERIFY_WITH_DELETION)
                    break;
                else
                    continue;
            }

            if (action.isError() && ConfigConstants.CONFIG_TRUNCATE_ACTIONS_AFTER_ERROR) {
                truncated = true;
                break;
            }

            prevActions.add(action);
        }

        /*
         * NOTE: The number of operations is highly related to intent-state transition.
         */

        int numPrevActions = prevActions.size();
        List<FuzzAction> newRandomActions = new ArrayList<>();
        TopoOperation prevTopoOperation = null;
        int numRemoval = rand.nextInt(IntentStateGuidanceConfigs.CONFIG_MAX_NUM_REMOVE_OPERATIONS +
                (truncated ? 0 : 1));
        for (int i = 0; i < prevActions.size() - numRemoval; i++) {
            FuzzAction prevAction = prevActions.get(i);
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
        int numActions = getNumAppendOperation(numPrevActions, numRemoval);

        FuzzAction prevAction = null;
        for (int i = 0; i < numActions; i++) {
            // purely generate random action.
            String actionId = String.format("%s-rand-%03d-%03d", newScenario.getName(),
                    newScenario.getFuzzCnt() + 1, ++actionNum);
            FuzzAction newAction = new FuzzAction(actionId);

            Intent targetIntent;
            String randomIntentStr;
            FuzzActionContent newContent;

            while (true) {
                // Get random alive intent
                String targetId = configIntentStore.getKeyOfRandomIntent(rand, true);
                int nextOperation = getRandOperationFromIntentId(targetId, prevAction);

                switch (nextOperation) {
                    case ADD_INTENT_OPERATION:
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

                    case MOD_INTENT_OPERATION:
                        // mod-intent
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

                    case WITHDRAW_INTENT_OPERATION:
                        // withdraw-intent
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

                    case PURGE_INTENT_OPERATION:
                        // purge-intent
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

                    case CHANGE_TOPO_OPERATION:
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
            prevAction = newAction;

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

        boolean isUnique = false;
        boolean isError = fuzzScenario.isError();
        boolean isSingleIntentDpError = fuzzScenario.isSingleIntentDpError();

        if (isError)
            numErrors ++;

        // update code coverage
        codeCoverage.updateCoverage(fuzzScenario.getCodeCoverage());
        int curHitCount = codeCoverage.getHitCount();

        // update state coverage
        IntentStateCoverage coverage = fuzzScenario.getIntentStateCoverage();
        globalIntentStateCoverage.updateCoverage(coverage);
        int curStateChangeCnt = coverage.getIntentStateChangeCnt();
        boolean newValue = stateCoverage.computeIfAbsent(curStateChangeCnt, k -> new HashSet<>())
                .add(ByteBuffer.wrap(coverage.toByteArray()).asReadOnlyBuffer());

        if (curStateChangeCnt > prevStateChangeCnt) {
            if (IntentStateGuidanceConfigs.CONFIG_ENBALE_ISTG) {
                seedScenarios.add(fuzzScenario);
            }

            log.info("## [StateChangeCnt] {} -> {} Add scenario into seeds: {} | cycle {} ##",
                    prevStateChangeCnt, curStateChangeCnt,
                    seedScenarios.size(), numCycles);
            prevStateChangeCnt = curStateChangeCnt;
            isUnique = true;

        } else if (newValue) {
            if (IntentStateGuidanceConfigs.CONFIG_ENBALE_ISTG)
                seedScenarios.add(fuzzScenario);

            log.info("## [StateTransition] {} into seeds: {} | cycle {} ##",
                    coverage.toHexString(),
                    seedScenarios.size(), numCycles);
            try {
                log.debug("[Interpret] {}", fuzzScenario.toJsonObject().toString());
                log.debug(coverage.toString());
            } catch (Exception ignored) {
            }
            // log.debug(IntentStateCoverage.toStringFromByteArray(coverage.toByteArray()));
            isUnique = true;
        }

        if (ccg.isUniqueCrash(fuzzScenario.getCodeCoverage()) > 0) {
            if (IntentStateGuidanceConfigs.CONFIG_ENABLE_CCG) {
                // Guidance finds new coverage path
                seedScenarios.add(fuzzScenario);
            }

            log.info("## [CodeCoverage] {} into seeds: {} | cycle {} ##",
                    curHitCount, seedScenarios.size(), numCycles);
            isUnique = true;
        }

        // log once for single-intent-dp-error
        if (hasSingleIntentDpError && isSingleIntentDpError) {
            isUnique = false;
        }

        if (isUnique && isError) {
            log.info("## {}: interesting bug", fuzzScenario.getName());
            fuzzScenario.setUniqueError();
            numUniqueErrors++;
        }

        if (isSingleIntentDpError) {
            hasSingleIntentDpError = true;
        }

        intentGuidance.feedbackResult(fuzzScenario);
        topologyIntentGuidance.feedbackResult(fuzzScenario);
        fuzzResult.addScenarioResult(fuzzScenario);

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
        return CodeCoverage.getStatsHeader()
                + ", " + IntentStateCoverage.getStatsHeader()
                + ", num ops, max IST cnt, IST entries, seed, cycles, errors, uniqueErrors";
    }

    @Override
    public String getStatsString() {
        // code-cov stats
        StringBuilder builder = new StringBuilder(codeCoverage.getStatsString());

        // intent-cov stats
        builder.append(", ").append(globalIntentStateCoverage.getStatsString());

        // guidance stats
        builder.append(", ").append(prevStateChangeCnt);
        builder.append(", ").append(stateCoverage.values().stream().mapToInt(Set::size).sum());
        builder.append(", ").append(seedScenarios.size());
        builder.append(", ").append(numCycles);
        builder.append(", ").append(numErrors);
        builder.append(", ").append(numUniqueErrors);

        return builder.toString();
    }

    @Override
    public String getResultsString() {
        return fuzzResult.getResultsString();
    }

    @Override
    public void addSeeds(Collection<FuzzScenario> fuzzScenarios) {
        // TODO
    }
}
