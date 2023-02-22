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

public class IntentModifyGuidance implements FuzzScenarioGuidance {

    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
    FuzzIntentGuidance intentGuidance;
    FuzzIntentGuidance configIntentGuidance;

    public IntentModifyGuidance() throws IllegalAccessException, InstantiationException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException {
        Class clazz = Class.forName("edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl." + ConfigConstants.CONFIG_FUZZING_INTENT_GUIDANCE);
        intentGuidance = (FuzzIntentGuidance) clazz.getDeclaredConstructor().newInstance();
        configIntentGuidance = (FuzzIntentGuidance) clazz.getDeclaredConstructor().newInstance();
    }

    @Override
    public void init(Object o) throws IOException, InterruptedException {
        intentGuidance.init(o);
        configIntentGuidance.init(o);
    }

    @Override
    public boolean stop() {
        configIntentGuidance.stop();
        return intentGuidance.stop();
    }

    @Override
    public FuzzScenario getRandomScenario(FuzzScenario scenario)
            throws IOException, JsonSyntaxException, EndFuzzException {
        FuzzScenario newScenario = FuzzScenario.copy(scenario);

        boolean isEqual = true;
        boolean changeConfig = false;
        while (true) {
            try {
                if (changeConfig) {
                    newScenario.clearConfigActions();
                    for (FuzzAction configAction : scenario.getConfigActions()) {
                        FuzzAction newConfigAction = this.getRandomConfigAction(configAction);
                        newScenario.addConfigAction(newConfigAction);
                        if (!newConfigAction.equals(configAction))
                            isEqual = false;
                    }

                    changeConfig = false;
                }
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

                if (!changeConfig) {
                    topoGuidance.resetMatrix();
                    changeConfig = true;
                    continue;
                }

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

                // Reset coverage
                topoGuidance.resetCoverage();

                // reset matrix of configIntentGuidance, as well
                ((TopologyIntentGuidance) configIntentGuidance).resetMatrix();
                ((TopologyIntentGuidance) configIntentGuidance).resetCoverage();
                changeConfig = true;

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
        configIntentGuidance.feedbackResult(fuzzScenario);
        return intentGuidance.feedbackResult(fuzzScenario);
    }

    private FuzzAction getRandomConfigAction(FuzzAction configAction) throws IOException, EndFuzzException {
        // copy first
        FuzzAction newAction = FuzzAction.copy(configAction);

        FuzzActionContent seedContent = configAction.getSeedContent();
        if (seedContent instanceof FuzzActionIntentContent) {

            // copy content from the seed
            FuzzActionIntentContent newContent = (FuzzActionIntentContent) seedContent.deepCopy();

            // get intent from the content
            String intent = newContent.getIntent();

            // generate random withdraw request..!
            String randomIntent = configIntentGuidance.getRandomIntentJson(intent);

            // set intent
            newContent.setIntent(randomIntent);

            // update content
            newAction.setContent(newContent);
        }

        return newAction;

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
