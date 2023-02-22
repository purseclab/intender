package edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.api;

import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Collection;

public interface FuzzScenarioGuidance {
    void init(Object o) throws IOException, InterruptedException;
    boolean stop();
    FuzzScenario getRandomScenario(FuzzScenario fuzzScenario) throws IOException, EndFuzzException;
    FuzzAction getRandomAction(FuzzAction action) throws IOException, EndFuzzException;
    boolean feedbackResult(@Nonnull FuzzScenario fuzzScenario);
    boolean doesRequireLogging(FuzzScenario scenario);
    public String getStatsHeader();
    public String getStatsString();
    public String getResultsString();
    void addSeeds(Collection<FuzzScenario> fuzzScenarios);
}
