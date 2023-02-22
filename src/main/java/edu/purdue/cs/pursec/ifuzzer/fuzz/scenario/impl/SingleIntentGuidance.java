package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl;

import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.GuidanceException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.ZestIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.ZestIntentGuidance.Input;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.api.FuzzScenarioGuidance;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionIntentContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

public class SingleIntentGuidance implements FuzzScenarioGuidance {

    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
    FuzzIntentGuidance intentGuidance;

    public SingleIntentGuidance() throws IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        Class clazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl." + ConfigConstants.CONFIG_FUZZING_INTENT_GUIDANCE);
        intentGuidance = (FuzzIntentGuidance) clazz.getDeclaredConstructor().newInstance();
    }

    @Override
    public void init(Object o) throws IOException, InterruptedException {
        intentGuidance.init(o);
    }

    @Override
    public boolean stop() {
        return intentGuidance.stop();
    }

    @Override
    public FuzzScenario getRandomScenario(FuzzScenario scenario)
            throws IOException, JsonSyntaxException, EndFuzzException, GuidanceException {
        FuzzScenario newScenario = FuzzScenario.copy(scenario);

        while (true) {
            boolean isEqual = true;
            try {
                newScenario.clearActionList();
                for (FuzzAction action : scenario.getActionList()) {
                    FuzzAction newAction = FuzzAction.fuzz(action);
                    newScenario.addAction(newAction);
                    if (!newAction.equals(action))
                        isEqual = false;
                }
            } catch (EndFuzzException e) {
                // Throw EndFuzzException except topology-aware fuzzing with mutation
                if (!ConfigConstants.CONFIG_ENABLE_MUTATE_TOPOLOGY ||
                        !(intentGuidance instanceof TopologyIntentGuidance)) {
                    throw e;
                }

                TopologyIntentGuidance topoGuidance = (TopologyIntentGuidance) intentGuidance;

                // Get random topology matrix from seed
                List<TopoOperation> syncOperations = topoGuidance.getSyncTopoOperationWithNewMatrix();
                newScenario.updateTopoOperations(topoGuidance.getCurrentMatrix());

                for (TopoOperation syncOperation : syncOperations) {
                    configTopoGraph.applyTopoOperation(syncOperation);
                    newScenario.addInitAction(syncOperation.toFuzzAction());
                    System.out.printf("*** Sync Topology:   %s %s ***\n",
                            syncOperation.getActionCmd(),
                            syncOperation.getNote());
                    System.out.flush();
                }

                // TODO: do not calculate whole matrix for every topoOperation
                topoGuidance.resetMatrix();

                TopoOperation prevOperation = null;
                for (int i = 0; i < new Random().nextInt(10) + 1; i++) {
                    // Get random operations from current matrix
                    TopoOperation topoOperation = topoGuidance.getRandomTopoOperationFromCurMatrix(prevOperation);

                    // Apply topology operation into config store
                    configTopoGraph.applyTopoOperation(topoOperation);
                    newScenario.addInitAction(topoOperation.toFuzzAction());
                    newScenario.addTopoOperation(topoOperation);
                    prevOperation = topoOperation;

                    topoGuidance.resetMatrix();
                    System.out.printf("*** Mutate Topology: %s %s ***\n",
                            topoOperation.getActionCmd(),
                            topoOperation.getNote());
                    System.out.flush();
                }
                topoGuidance.resetCoverage();

                // fuzz again
                continue;
            }

            // AFL generates the same input in start stage.
            if (!isEqual) {
                newScenario.incFuzzCnt();
                newScenario.setFuzzed(true);
            }

            // break when scenario is successfully fuzzed
            break;
        }

        return newScenario;
    }

    @Override
    public boolean feedbackResult(@Nonnull FuzzScenario fuzzScenario) {
        return intentGuidance.feedbackResult(fuzzScenario);
    }

    @Override
    public FuzzAction getRandomAction(FuzzAction action) throws IOException, EndFuzzException, GuidanceException {
        // copy first
        FuzzAction newAction = FuzzAction.copy(action);

        FuzzActionContent seedContent = action.getSeedContent();
        if (seedContent instanceof FuzzActionIntentContent) {

            // copy content from the seed
            FuzzActionIntentContent newContent = (FuzzActionIntentContent) seedContent.deepCopy();

            // get intent from the content
            if (intentGuidance instanceof ZestIntentGuidance) {
                // get random inputStream
                Input input = newContent.getIntentInput();
                Input newInput = ((ZestIntentGuidance)intentGuidance).getRandomIntentJson(input);
                newContent.setIntentInput(newInput);
            } else {
                // get pure intent string
                String intentStr = newContent.getIntent();
                String newIntentStr = intentGuidance.getRandomIntentJson(intentStr);
                newContent.setIntent(newIntentStr);
            }

            // update content
            newAction.setContent(newContent);
        }

        return newAction;
    }

    @Override
    public boolean doesRequireLogging(FuzzScenario scenario) {
        return intentGuidance.doesRequireLogging(scenario);
    }

    public FuzzIntentGuidance getIntentGuidance() {
        return this.intentGuidance;
    }

    @Override
    public String getStatsHeader() {
        return intentGuidance.getStatsHeader();
    }

    @Override
    public String getStatsString() {
        return intentGuidance.getStatsString();
    }

    @Override
    public String getResultsString() {
        return intentGuidance.getResultsString();
    }

    @Override
    public void addSeeds(Collection<FuzzScenario> fuzzScenarios) {
        ArrayList<FuzzAction> fuzzActions = new ArrayList<>();
        for (FuzzScenario fuzzScenario : fuzzScenarios) {
            for (FuzzAction fuzzAction : fuzzScenario.getActionList()) {
                if (fuzzAction.getContent() instanceof FuzzActionIntentContent) {
                    fuzzActions.add(fuzzAction);
                }
            }
        }

        intentGuidance.addSeeds(fuzzActions);
    }

    public static IntentInterfaceResponse getIntentReqResponse(FuzzScenario fuzzScenario) {
        for (FuzzAction action : fuzzScenario.getActionList()) {
            if (action.getContent() instanceof FuzzActionIntentContent) {
                IntentInterfaceResponse response = action.getResponse();
                return response;
            }
        }

        return null;
    }

    public static int getIntentReqStatusCode(FuzzScenario fuzzScenario) {
        IntentInterfaceResponse response = getIntentReqResponse(fuzzScenario);

        if (response == null)
            return 0;

        return response.getStatusCode();
    }

    public static String getIntentStr(FuzzScenario fuzzScenario) {
        for (FuzzAction action : fuzzScenario.getActionList()) {
            if (action.getContent() instanceof FuzzActionIntentContent) {
                FuzzActionIntentContent intentContent = (FuzzActionIntentContent) action.getContent();
                return intentContent.getIntent();
            }
        }
        return null;
    }

    public static Object getCpVerifiedIntent(FuzzScenario fuzzScenario) {
        for (FuzzAction action : fuzzScenario.getActionList()) {
            if (action.getActionCmd().equals("cp-verify-intent")) {
                return action.getRetObject();
            }
        }
        return null;
    }
}
