package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl;

import com.google.gson.*;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.SingleIntentFuzzResult;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.api.ONOSConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.TopologyIntentGuidanceConfigs;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.SingleIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentType;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoMatrix;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.util.*;

public class TopologyIntentGuidance implements FuzzIntentGuidance {
    private static Logger log = LoggerFactory.getLogger(TopologyIntentGuidance.class);
    private TopoGraph topoGraph;
    private TopoMatrix currentMatrix;
    private int prevHitCount = 0;
    List<TopoMatrix> seedTopologies = new LinkedList<>();
    private int curSeedIdx = -1, numCycles = -1;
    public static Random random = new Random();
    CodeCoverage codeCoverage;

    private SingleIntentFuzzResult fuzzResult;
    private Map<Integer, Integer> responseMap;

    @Override
    public String getRandomIntentJson(String targetJsonStr) throws JsonSyntaxException, EndFuzzException {
        JsonObject targetJson;
        IntentType intentType;

        boolean doesGenRandomIntent = ((targetJsonStr == null) || TopologyIntentGuidanceConfigs.CONFIG_RANDOM_TOPOLOGY);
        boolean isPazz = ConfigConstants.CONFIG_FUZZING_PACKET_GUIDANCE.equals("PazzPacketGuidance");

        if (doesGenRandomIntent) {
            targetJson = new JsonObject();
            intentType = isPazz ? IntentType.PointToPointIntent :
                         random.nextBoolean() ? IntentType.HostToHostIntent : IntentType.PointToPointIntent;

            targetJson.addProperty("type", intentType.toString());
            targetJson.addProperty("appId", ONOSConstants.ONOS_APP_ID);
            targetJson.addProperty("priority", ONOSConstants.ONOS_INTENT_DEFAULT_PRIORITY);  /* TODO: fuzz priority */

        } else {
            targetJson = JsonParser.parseString(targetJsonStr).getAsJsonObject();

            if (!targetJson.has("type"))
                throw new JsonSyntaxException("No type field");

            String intentTypeStr = targetJson.get("type").getAsString();
            if (intentTypeStr.equals(IntentType.PointToPointIntent.toString())) {
                intentType = IntentType.PointToPointIntent;
            } else if (intentTypeStr.equals(IntentType.HostToHostIntent.toString())) {
                intentType = IntentType.HostToHostIntent;
            } else {
                throw new JsonSyntaxException("Not supported type: " + intentTypeStr);
            }
        }

        if (!hasCurrentMatrix())
            initCurrentMatrix(topoGraph);

        if (intentType.equals(IntentType.PointToPointIntent)) {
            log.debug("Original: {}", targetJson.toString());
            if (doesGenRandomIntent)
                currentMatrix.getRandomPointToPointIntent(targetJson);
            else
                currentMatrix.getNextPointToPointIntent(targetJson);

            if (isPazz) {
                JsonObject selectorJson = new JsonObject();
                JsonArray criteriaJsonArr = new JsonArray();
                JsonObject criterionJson = new JsonObject();
                criterionJson.addProperty("type", "ETH_TYPE");
                criterionJson.addProperty("ethType", "0x800");
                criteriaJsonArr.add(criterionJson);
                criterionJson = new JsonObject();
                criterionJson.addProperty("type", "IPV4_DST");
                /* generate random dst IP address */
                criterionJson.addProperty("ip", FuzzUtil.randomIpWithCidr(random));
                criteriaJsonArr.add(criterionJson);
                selectorJson.add("criteria", criteriaJsonArr);
                targetJson.add("selector", selectorJson);
            }

            log.debug("Fuzzed: {}", targetJson.toString());

        } else if (intentType.equals(IntentType.HostToHostIntent)) {
            log.debug("Original: {}", targetJson.toString());
            if (doesGenRandomIntent)
                currentMatrix.getRandomHostToHostIntent(targetJson);
            else
                currentMatrix.getNextHostToHostIntent(targetJson);

            log.debug("Fuzzed: {}", targetJson.toString());

        } else {
            throw new JsonSyntaxException("Not supported type: " + intentType.toString());
        }

        return targetJson.toString();
    }

    public void resetMatrix() {
        if (currentMatrix != null) {
            currentMatrix.setInit(false);
        }
    }

    public TopoMatrix getCurrentMatrix() {
        return currentMatrix;
    }

    public TopoOperation getRandomTopoOperation() {
        if (!hasCurrentMatrix())
            initCurrentMatrix(topoGraph);
        return currentMatrix.getRandomTopoOperation();
    }

    public TopoOperation getRandomTopoOperationFromCurMatrix() {
        return getRandomTopoOperationFromCurMatrix(null);
    }

    public TopoOperation getRandomTopoOperationFromCurMatrix(TopoOperation prevOperation) {
        if (!hasCurrentMatrix())
            initCurrentMatrix(topoGraph);

        TopoOperation prevRevertOperation = prevOperation != null ? prevOperation.invert() : null;
        TopoOperation newOperation;
        do {
            // Allow if new operation is NOT reverse of prev operation.
            newOperation = currentMatrix.getRandomTopoOperation();
        } while (newOperation.typeEquals(prevRevertOperation));

        currentMatrix.addTopoOperation(newOperation);

        return newOperation;
    }

    public List<TopoOperation> getSyncTopoOperationWithNewMatrix() {
        if (!hasCurrentMatrix())
            initCurrentMatrix(topoGraph);

        int curHitCount = this.getCodeCoverage().getHitCount();
        if (prevHitCount < curHitCount) {
            // Guidance finds new coverage path
            seedTopologies.add(currentMatrix);
            log.info("## Add new matrix {} -> {} into seeds: {} ##",
                    prevHitCount, curHitCount,
                    seedTopologies.size());
            prevHitCount = curHitCount;
        }

        // TODO: weight the minimum difference between current and next seed
        curSeedIdx = (curSeedIdx + 1) % seedTopologies.size();
        if (curSeedIdx == 0)
            numCycles ++;

        TopoMatrix seedMatrix = seedTopologies.get(curSeedIdx);

        if (seedMatrix == null) {
            seedMatrix = currentMatrix;
            log.warn("## There is no SEED for topology mutation. ##");
        } else if (seedMatrix.equals(currentMatrix)) {
            log.info("## Current is same with seed ##");
        } else {
            log.debug("## Get {}/{} seed / {} cycle(s)", curSeedIdx, seedTopologies.size(), numCycles);
        }

        // Get diff operations
        List<TopoOperation> syncOperations = seedMatrix.getDiffTopoOperations(currentMatrix);

        // Copy seedMatrix into currentMatrix
        currentMatrix = seedMatrix.copy();

        return syncOperations;
    }

    public boolean updateTopoOperation(TopoOperation oldOperation, TopoOperation newOperation) {
        if (!hasCurrentMatrix())
            return false;

        return currentMatrix.updateTopoOperation(oldOperation, newOperation);
    }

    public void resetCoverage() {
        this.codeCoverage = null;
    }

    public void updateCoverage(CodeCoverage that) {
        if (this.codeCoverage == null)
            this.codeCoverage = new CodeCoverage();

        this.codeCoverage.updateCoverage(that);
    }

    public CodeCoverage getCodeCoverage() {
        return this.codeCoverage;
    }

    @Override
    public boolean feedbackResult(@Nonnull FuzzScenario parentScenario) {
        if (!hasCurrentMatrix())
            initCurrentMatrix(topoGraph);

        // append coverage data
        this.updateCoverage(parentScenario.getCodeCoverage());

        // add results
        int code = SingleIntentGuidance.getIntentReqStatusCode(parentScenario);
        if (code > 0)
            responseMap.put(code, responseMap.getOrDefault(code, 0) + 1);
        fuzzResult.addSingleIntentResult(parentScenario);

        return true;
    }

    @Override
    public boolean init(Object o) {
        assert (o instanceof TopoGraph);
        fuzzResult = new SingleIntentFuzzResult();
        responseMap = new HashMap<>();
        topoGraph = (TopoGraph)o;
        currentMatrix = null;
        return true;
    }

    @Override
    public boolean stop() {
        seedTopologies.clear();
        return true;
    }

    @Override
    public boolean isCoverageGuided() {
        return false;
    }

    @Override
    public boolean doesRequireLogging(FuzzScenario scenario) {
        if (!scenario.isFuzzed())
            return false;

        if (!scenario.isAccepted())
            return true;

        if (!scenario.isVerified())
            return true;

        return false;
    }

    @Override
    public String getStatsHeader() {
        return CodeCoverage.getStatsHeader() + ", " + SingleIntentFuzzResult.getStatsHeader();
    }

    @Override
    public String getStatsString() {
        return codeCoverage.getStatsString() + ", " + fuzzResult.getStatsString();
    }

    @Override
    public String getResultsString() {
        return fuzzResult.getResultsString();
    }


    private void initCurrentMatrix(TopoGraph topoGraph) {
        if (currentMatrix == null)
            currentMatrix = new TopoMatrix();

        if (!currentMatrix.isInit())
            currentMatrix.initialize(topoGraph);
    }

    private boolean hasCurrentMatrix() {
        if (currentMatrix == null)
            return false;

        return currentMatrix.isInit();
    }

    @Override
    public void addSeeds(Collection<FuzzAction> fuzzActions) {
        // TODO
    }
}
