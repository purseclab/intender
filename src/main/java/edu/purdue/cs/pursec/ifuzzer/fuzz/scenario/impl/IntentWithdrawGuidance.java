package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl;

import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.TopologyIntentGuidance;
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
import java.util.Collection;
import java.util.List;
import java.util.Random;

public class IntentWithdrawGuidance implements FuzzScenarioGuidance {

    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
    FuzzIntentGuidance intentGuidance;

    public IntentWithdrawGuidance() throws IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
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
            throws IOException, JsonSyntaxException, EndFuzzException {
        FuzzScenario newScenario = FuzzScenario.copy(scenario);

        while (true) {
            boolean isEqual = true;
            try {
                // For withdrawal, fuzzing mutates init-actions of scenario, not actions.
                newScenario.clearConfigActions();
                for (FuzzAction configAction : scenario.getConfigActions()) {
                    FuzzAction newConfigAction = FuzzAction.fuzz(configAction);
                    newScenario.addConfigAction(newConfigAction);
                    if (!newConfigAction.equals(configAction))
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

                // Reset coverage data
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
        return intentGuidance.doesRequireLogging(scenario);
    }

    public FuzzIntentGuidance getIntentGuidance() {
        return this.intentGuidance;
    }

    @Override
    public String getStatsHeader() {
        return null;
    }

    @Override
    public String getStatsString() {
        return null;
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
