package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl;

import com.google.gson.JsonSyntaxException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.api.FuzzScenarioGuidance;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionIntentContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

public class TopologyOperationGuidance implements FuzzScenarioGuidance {

    private static Logger log = LoggerFactory.getLogger(TopologyOperationGuidance.class);
    private static final TopoGraph configTopoGraph = TopoGraph.getConfigTopology();
//    FuzzIntentGuidance intentGuidance;
    TopologyIntentGuidance topologyIntentGuidance;
    CodeCoverage codeCoverage;
    List<FuzzScenario> seedScenarios = new LinkedList<>();
    private int prevHitCount = 0;
    private int curSeedIdx = -1, numCycles = -1;

    public TopologyOperationGuidance() {
        topologyIntentGuidance = new TopologyIntentGuidance();
    }

    @Override
    public void init(Object o) throws IOException, InterruptedException {
        // object will be ConfigTopoGraph
        topologyIntentGuidance.init(o);
    }

    @Override
    public boolean stop() {
        seedScenarios.clear();
        codeCoverage = null;
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

    @Override
    public FuzzScenario getRandomScenario(FuzzScenario scenario)
            throws IOException, JsonSyntaxException, EndFuzzException {
        FuzzScenario newScenario = FuzzScenario.copy(scenario);
        FuzzScenario seedScenario = scenario;

        boolean isEqual = true;

        while (true) {
            try {
                // For topo-change, fuzzing mutates init-actions of scenario, not actions.
                newScenario.clearConfigActions();
                for (FuzzAction configAction : seedScenario.getConfigActions()) {
                    FuzzAction newConfigAction = FuzzAction.fuzz(configAction);
                    newScenario.addConfigAction(newConfigAction);
                    if (!newConfigAction.equals(configAction))
                        isEqual = false;
                }

            } catch (EndFuzzException e) {
                // Throw EndFuzzException except topology-aware fuzzing with mutation
//                if (!ConfigConstants.CONFIG_ENABLE_MUTATE_TOPOLOGY ||
//                        !(intentGuidance instanceof TopologyIntentGuidance)) {
//                    throw e;
//                }

                // use code coverage
                if (codeCoverage != null) {
                    int curHitCount = codeCoverage.getHitCount();
                    if (prevHitCount < curHitCount) {
                        // Guidance finds new coverage path
                        seedScenarios.add(scenario);
                        seedScenarios.add(getInvertScenario(scenario));

                        log.info("## Add new matrix {} -> {} into seeds: {} | cycle {} ##",
                                prevHitCount, curHitCount,
                                seedScenarios.size(), numCycles);
                        prevHitCount = curHitCount;
                    }
                }

                curSeedIdx = (curSeedIdx + 1) % seedScenarios.size();
                if (curSeedIdx == 0)
                    numCycles ++;

                seedScenario = seedScenarios.get(curSeedIdx);
                newScenario = FuzzScenario.copy(seedScenario);
                newScenario.setFuzzCnt(scenario.getFuzzCnt());

                // Apply diff of prev scenario and next scenario
                List<TopoOperation> updateTopoOperations = FuzzUtil.getDiffTopoOperations(
                        getTopoOperationFromFuzzAction(scenario.getConfigActions()),
                        getTopoOperationFromFuzzAction(newScenario.getConfigActions()));

                for (TopoOperation operation : updateTopoOperations) {
                    log.debug("## Mutate Topology:   {} {} ***\n", operation.getActionCmd(), operation.getNote());
                    configTopoGraph.applyTopoOperation(operation);
                }

                topologyIntentGuidance.resetMatrix();
                newScenario.clearActionList();
                for (FuzzAction action : seedScenario.getActionList()) {
                    FuzzAction newAction = this.getRandomTopoAction(action);
                    newScenario.addAction(newAction);
                    if (!newAction.equals(action))
                        isEqual = false;
                }

                codeCoverage = null;

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
        if (codeCoverage == null)
            codeCoverage = new CodeCoverage();

        codeCoverage.updateCoverage(fuzzScenario.getCodeCoverage());

        return topologyIntentGuidance.feedbackResult(fuzzScenario);
//        intentGuidance.feedbackResult(fuzzScenario);
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
    public FuzzAction getRandomAction(FuzzAction action) throws EndFuzzException {
        // copy first
        FuzzAction newAction = FuzzAction.copy(action);

        FuzzActionContent seedContent = action.getSeedContent();
        if (seedContent instanceof FuzzActionIntentContent) {

            // copy content from the seed
            FuzzActionIntentContent newContent = (FuzzActionIntentContent) seedContent.deepCopy();

            // get intent from the content
            String intent = newContent.getIntent();

            // generate random withdraw request..!
            String randomIntent = topologyIntentGuidance.getRandomIntentJson(intent);

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
