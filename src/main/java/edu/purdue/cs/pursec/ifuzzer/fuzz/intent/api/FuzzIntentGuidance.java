package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Collection;

public interface FuzzIntentGuidance {
    static final String[] targetKeys = {"one", "two", "egressPoint", "ingressPoint"};
    String getRandomIntentJson(String targetJsonStr) throws IOException, EndFuzzException;
    boolean init(Object o) throws IOException, InterruptedException;
    boolean stop();
    boolean isCoverageGuided();
    boolean doesRequireLogging(FuzzScenario scenario);
    boolean feedbackResult(@Nonnull FuzzScenario parentScenario);
    public String getStatsHeader();
    public String getStatsString();
    public String getResultsString();
    void addSeeds(Collection<FuzzAction> fuzzActions);
}
