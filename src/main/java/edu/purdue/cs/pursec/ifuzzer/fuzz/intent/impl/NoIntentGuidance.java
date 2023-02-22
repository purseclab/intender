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

public class NoIntentGuidance implements FuzzIntentGuidance {

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

        System.out.printf("There are %d keys in the intent\n", keyList.size());

        // return without change
        if (keyList.size() <= 0)
            return targetJsonStr;

        String targetKey = keyList.get(rand.nextInt(keyList.size()));
        JsonElement jsonElement = targetJson.get(targetKey);

        if (jsonElement.isJsonObject()) {
            // Single-Point (JsonObject)
            JsonObject jsonObject = targetJson.get(targetKey).getAsJsonObject();
            // Mutation-Based
            targetJson.add(targetKey, FuzzUtil.blackboxFuzzPoint(jsonObject, rand));

        } else if (jsonElement.isJsonArray()) {
            // Multi-Point (JsonArray)
            JsonArray jsonArray = targetJson.get(targetKey).getAsJsonArray();   // get jsonArray
            int idx = rand.nextInt(jsonArray.size());                           // choose idx in jsonArray
            JsonObject jsonObject = jsonArray.get(idx).getAsJsonObject();       // get jsonObject

            // Mutation-Based
            jsonArray.set(idx, FuzzUtil.blackboxFuzzPoint(jsonObject, rand));              // set new random json in jsonArray
            targetJson.add(targetKey, jsonArray);                               // set new array

        } else {
            // Host (String)
            if (targetKey.equals("one") || targetKey.equals("two")) {
                String target = targetJson.get(targetKey).getAsString();
                targetJson.addProperty(targetKey, FuzzUtil.blackboxFuzzString(target, rand));
            }
        }

        return targetJson.toString();
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
