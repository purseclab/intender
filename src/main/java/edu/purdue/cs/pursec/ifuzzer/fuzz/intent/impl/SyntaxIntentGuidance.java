package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl;

import com.google.gson.*;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FuzzIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;

import javax.annotation.Nonnull;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;

public class SyntaxIntentGuidance implements FuzzIntentGuidance {

    private final Random rand = new Random();

    @Override
    public String getRandomIntentJson(String targetJsonStr) throws JsonSyntaxException {
        JsonObject targetJson = JsonParser.parseString(targetJsonStr).getAsJsonObject();

        List<String> keyList = new ArrayList<>();
        for (String targetKey : targetKeys) {
            if (targetJson.has(targetKey)) {
                keyList.add(targetKey);
            }
        }

        // return without change
        if (keyList.size() <= 0)
            return targetJsonStr;

        String targetKey = keyList.get(rand.nextInt(keyList.size()));
        JsonElement jsonElement = targetJson.get(targetKey);

        if (jsonElement.isJsonObject()) {
            // Generation-Based
            targetJson.add(targetKey, randomValidFuzzPoint());

        } else if (jsonElement.isJsonArray()) {
            // Multi-Point (JsonArray)
            JsonArray jsonArray = targetJson.get(targetKey).getAsJsonArray();   // get jsonArray
            int idx = rand.nextInt(jsonArray.size());                           // choose idx in jsonArray

            // Generation-Based
            jsonArray.set(idx, randomValidFuzzPoint());
            targetJson.add(targetKey, jsonArray);                               // set new array

        } else {
            // Host (String)
            if (targetKey.equals("one") || targetKey.equals("two")) {
                targetJson.addProperty(targetKey, FuzzUtil.randomValidHostId(rand));
            }
        }

        return targetJson.toString();
    }

    private JsonObject randomValidFuzzPoint() {
        JsonObject pointJson = new JsonObject();

        pointJson.addProperty("device", FuzzUtil.randomValidDpid(true, rand));
        pointJson.addProperty("port", String.valueOf(FuzzUtil.randomPortNo(rand)));

        return pointJson;
    }

    @Override
    public boolean init(Object o) {
        return true;
    }

    @Override
    public boolean stop() {
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

        if (scenario.isVerified())
            return true;

        return false;
    }

    @Override
    public boolean feedbackResult(@Nonnull FuzzScenario parentScenario) {
        return false;
    }

    @Override
    public String getStatsHeader() {
        // TODO
        return null;
    }

    @Override
    public String getStatsString() {
        // TODO
        return null;
    }

    @Override
    public String getResultsString() {
        return null;
    }

    @Override
    public void addSeeds(Collection<FuzzAction> fuzzActions) {
        // TODO
    }
}