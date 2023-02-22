package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl;

import com.google.gson.JsonObject;
import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.SingleIntentFuzzResult;
import edu.purdue.cs.pursec.ifuzzer.cli.FuzzCommand;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CodeCoverage;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.CoverageGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.GuidanceException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.*;
import edu.purdue.cs.pursec.ifuzzer.fuzz.scenario.impl.SingleIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzActionIntentContent;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.ec.ECDSAOperations.Seed;

import javax.annotation.Nonnull;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static java.lang.Math.ceil;
import static java.lang.Math.log;

public class ZestIntentGuidance implements FuzzIntentGuidance {
    private static Logger log = LoggerFactory.getLogger(ZestIntentGuidance.class);

    /** A pseudo-random number generator for generating fresh values. */
    protected Random random = new Random();
    protected File savedCorpusDirectory = null;
    protected ArrayList<Input> savedInputs = new ArrayList<>();
    protected Deque<Input> seedInputs = new ArrayDeque<>();
    /** Current input that's running -- valid after getRandomIntentJson() and before feedbackResult(). */
    protected Input<?> currentInput;
    /** Index of currentInput in the savedInputs -- valid after seeds are processed (OK if this is inaccurate). */
    protected int currentParentInputIdx = 0;
    /** Number of mutated inputs generated from currentInput. */
    protected int numChildrenGeneratedForCurrentParentInput = 0;
    /** Number of cycles completed (i.e. how many times we've reset currentParentInputIdx to 0. */
    protected int cyclesCompleted = 0;
    /** Number of favored inputs in the last cycle. */
    protected int numFavoredLastCycle = 0;
    /** The currently executing input (for debugging purposes). */
    protected File currentInputFile;
    /** Date when last run was started. */
    protected Date runStart;
    /** Number of conditional jumps since last run was started. */
    protected long branchCount;

    CodeCoverage wholeCoverage;
    CodeCoverage totalCoverage;
    CodeCoverage validCoverage;
    CoverageGuidance ccg;

    /** Number of saved inputs.
     *
     * This is usually the same as savedInputs.size(),
     * but we do not really save inputs in TOTALLY_RANDOM mode.
     */
    protected int numSavedInputs = 0;
    protected long numTrials = 0;
    protected long numValid = 0;
    protected long numError = 0;
    protected long numUniqueError = 0;
    protected int maxCoverage = 0;
    protected boolean isStarted = false;

    /** A mapping of coverage keys to inputs that are responsible for them. */
    protected Map<Object, Input> responsibleInputs = new HashMap<>(ConfigConstants.COVERAGE_MAP_SIZE);
    /* stats */
    private SingleIntentFuzzResult fuzzResult;
    private Map<Integer, Integer> responseMap;

    protected InputStream createParameterStream() {
        // Return an input stream that reads bytes from a linear array
        return new InputStream() {
            int bytesRead = 0;

            @Override
            public int read() throws IOException {
                assert currentInput instanceof LinearInput : "ZestGuidance should only mutate LinearInput(s)";

                // For linear inputs, get with key = bytesRead (which is then incremented)
                LinearInput linearInput = (LinearInput) currentInput;
                // Attempt to get a value from the list, or else generate a random value
                int ret = linearInput.getOrGenerateFresh(bytesRead++, random);
                // infoLog("read(%d) = %d", bytesRead, ret);
                return ret;
            }
        };
    }

    private void resetCurrentInput() {
        if (!seedInputs.isEmpty()) {
            // First, if we have some specific seeds, use those
            currentInput = seedInputs.removeFirst();

            // Hopefully, the seeds will lead to new coverage and be added to saved inputs

        } else if (savedInputs.isEmpty()) {
            // If no seeds given try to start with something random
            if (numTrials > 100_000) {
                throw new GuidanceException("Too many trials without coverage; " +
                        "likely all assumption violations");
            }

            // Make fresh input using either list or maps
            // infoLog("Spawning new input from thin air");
            currentInput = createFreshInput();
        } else {
            // The number of children to produce is determined by how much of the coverage
            // pool this parent input hits
            Input currentParentInput = savedInputs.get(currentParentInputIdx);
            int targetNumChildren = getTargetChildrenForParent(currentParentInput);
            if (numChildrenGeneratedForCurrentParentInput >= targetNumChildren) {
                // Select the next saved input to fuzz
                currentParentInputIdx = (currentParentInputIdx + 1) % savedInputs.size();

                // Count cycles
                if (currentParentInputIdx == 0) {
                    completeCycle();
                }

                numChildrenGeneratedForCurrentParentInput = 0;
            }
            Input parent = savedInputs.get(currentParentInputIdx);

            // Fuzz it to get a new input
            // infoLog("Mutating input: %s", parent.desc);
            currentInput = parent.fuzz(random);
            numChildrenGeneratedForCurrentParentInput++;

            // Write it to disk for debugging
            try {
                writeCurrentInputToFile(currentInputFile);
            } catch (IOException ignore) { }

            // Start time-counting for timeout handling
            this.runStart = new Date();
            this.branchCount = 0;
        }

    }

    @Override
    public String getRandomIntentJson(String seedRandomStr) throws IOException, EndFuzzException, GuidanceException {
        /* XXX: NOT USED */
        if (!isStarted)
            start(seedRandomStr);

        resetCurrentInput();

        InputStream inputStream = createParameterStream();

        // Generate input values
        return FuzzUtil.getIntentJsonFromGenerator(inputStream).toString();
    }

    public Input getRandomIntentJson(Input input) throws IOException {
        if (!isStarted)
            start(input);

        resetCurrentInput();

        return currentInput;
    }

    private int getTargetChildrenForParent(Input parentInput) {
        // Baseline is a constant
        int target = ZestIntentGuidanceConfigs.NUM_CHILDREN_BASELINE;

        // We like inputs that cover many things, so scale with fraction of max
        if (maxCoverage > 0) {
            target = (ZestIntentGuidanceConfigs.NUM_CHILDREN_BASELINE * parentInput.hitCoverage) / maxCoverage;
        }

        // We absolutely love favored inputs, so fuzz them more
        if (parentInput.isFavored()) {
            target = target * ZestIntentGuidanceConfigs.NUM_CHILDREN_MULTIPLIER_FAVORED;
        }

        return target;
    }

    /** Handles the end of fuzzing cycle (i.e., having gone through the entire queue) */
    protected void completeCycle() {
        // Increment cycle count
        cyclesCompleted++;
        log.info("# Cycle " + cyclesCompleted + " completed.");

        // Go over all inputs and do a sanity check (plus log)
        log.info("Here is a list of favored inputs:");
        int sumResponsibilities = 0;
        numFavoredLastCycle = 0;
        for (Input input : savedInputs) {
            if (input.isFavored()) {
                int responsibleFor = input.responsibilities.size();
                log.info("Input {} is responsible for {} branches", input.id, responsibleFor);
                sumResponsibilities += responsibleFor;
                numFavoredLastCycle++;
            }
        }
        int totalCoverageCount = totalCoverage.getHitCount();
        log.info("Total {} branches covered", totalCoverageCount);
        if (sumResponsibilities != totalCoverageCount) {
            throw new AssertionError("Responsibilty mistmatch");
        }

        // Break log after cycle
        log.info("\n\n\n");
    }

    protected Input<?> createFreshInput() {
        return new LinearInput();
    }

    @Override
    public boolean init(Object o) throws IOException, InterruptedException {
        fuzzResult = new SingleIntentFuzzResult();
        responseMap = new HashMap<>();

        /* create corpus */
        String corpusPath = FuzzCommand.logDir + File.separator + "corpus";
        savedCorpusDirectory = new File(corpusPath);
        if (!savedCorpusDirectory.exists()) {
            if (!savedCorpusDirectory.mkdir()) {
                System.err.printf("Cannot create %s\n", savedCorpusDirectory);
                System.exit(2);
            }
        }

        this.currentInputFile = new File(FuzzCommand.logDir, ".cur_input");
        return false;
    }

    @Override
    public boolean stop() {
        isStarted = false;
        return true;
    }

    @Override
    public boolean isCoverageGuided() {
        return true;
    }

    @Override
    public boolean doesRequireLogging(FuzzScenario scenario) {
        if (!scenario.isFuzzed())
            return false;

        if (!scenario.isAccepted()) {
            int code = SingleIntentGuidance.getIntentReqStatusCode(scenario);
            if (code >= 200 && code < 300) {
                return true;
            } else if (responseMap.getOrDefault(code, 0) <= 1) {
                return true;
            }
        } else {
            String intentStr = SingleIntentGuidance.getIntentStr(scenario);
            try {
                JsonObject intentJson = TestUtil.fromJson(intentStr);
            } catch (Exception e) {
                // unlikely ...
                return true;
            }
        }

        if (scenario.isError())
            return true;

        if (scenario.isVerified())
            return true;

        return false;
    }

    @Override
    public String getStatsHeader() {
        return CodeCoverage.getStatsHeader() + ", " + SingleIntentFuzzResult.getStatsHeader() +
                ", trials, valid, cycles, error, uniqueError";
    }

    @Override
    public String getStatsString() {
        return totalCoverage.getStatsString() +
                ", " + validCoverage.getStatsString(false) +
                ", " + fuzzResult.getStatsString() +
                ", " + numTrials + ", " + numValid + ", " + cyclesCompleted +
                ", " + numError + ", " + numUniqueError;
    }

    @Override
    public String getResultsString() {
        return fuzzResult.getResultsString();
    }

    @Override
    public boolean feedbackResult(@Nonnull FuzzScenario scenario) {
        if (currentInput == null) {
            // just run once again
            return false;
        }

        boolean valid = scenario.isAccepted();
        this.numTrials++;
        if (valid)
            numValid++;

        // add results
        int code = SingleIntentGuidance.getIntentReqStatusCode(scenario);
        if (code > 0)
            responseMap.put(code, responseMap.getOrDefault(code, 0) + 1);
        fuzzResult.addSingleIntentResult(scenario);

        CodeCoverage runningCoverage = scenario.getCodeCoverage();

        if (valid || scenario.isSuccess()) {

            int hitCountBefore = totalCoverage.getHitCount();
            int validHitCountBefore = validCoverage.getHitCount();

            // Compute a list of keys for which this input can assume responsibility.
            // Newly covered branches are always included.
            // Existing branches *may* be included, depending on the heuristics used.
            // A valid input will steal responsibility from invalid inputs

            Set<Object> responsibilities = computeResponsibilities(runningCoverage, valid);

            // update coverages
            wholeCoverage.updateCoverage(runningCoverage);
            boolean coverageBitsUpdated = totalCoverage.updateCoverage(runningCoverage);
            if (valid)
                validCoverage.updateCoverage(runningCoverage);

            int hitCountAfter = totalCoverage.getHitCount();
            if (hitCountAfter > maxCoverage)
                maxCoverage = hitCountAfter;
            int validHitCountAfter = validCoverage.getHitCount();

            boolean toSave = false;
            String why = "";

            if (coverageBitsUpdated) {
                toSave = true;
                why += "+count";
            }

            if (hitCountAfter > hitCountBefore) {
                toSave = true;
                why += "+cov";
            }

            if (validHitCountAfter > validHitCountBefore) {
                toSave = true;
                why += "+valid";
            }

            if (toSave) {
                currentInput.gc();
                log.debug("Saving new input (at run {}): input #{} " +
                                "of size {}; total coverage = {}",
                        numTrials, savedInputs.size(), currentInput.size(), hitCountAfter);

                // Save input to queue and to disk
                final String reason = why;
                GuidanceException.wrap(() -> saveCurrentInput(scenario.getCodeCoverage(), responsibilities, reason));
            }

        } else if (scenario.isError()) {
            numError ++;
//            Collection<?> newCovList = runningCoverage.computeNewCoverage(totalCoverage);

            // While Zest checks stacktrace for uniqueness, but there is no definite stack with semantic error.
            if (ccg.isUniqueCrash(runningCoverage) > 0) {
                scenario.setUniqueError();
                numUniqueError ++;

                currentInput.gc();
            }
        }

        return false;
    }

    // Compute a set of branches for which the current input may assume responsibility
    private Set<Object> computeResponsibilities(CodeCoverage coverage, boolean valid) {
//        Set<Object> result = new HashSet<>();
        Set<Object> result = ConcurrentHashMap.newKeySet();

        // This input is responsible for all new coverage
        Collection<?> newCoverage = coverage.computeNewCoverage(totalCoverage);
        if (newCoverage.size() > 0) {
            result.addAll(newCoverage);
        }

        // If valid, this input is responsible for all new valid coverage
        if (valid) {
            Collection<?> newValidCoverage = coverage.computeNewCoverage(validCoverage);
            if (newValidCoverage.size() > 0) {
                result.addAll(newValidCoverage);
            }
        }

        return result;
    }

    protected void writeCurrentInputToFile(File saveFile) throws IOException {
        try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(saveFile))) {
            for (Integer b : currentInput) {
                assert (b >= 0 && b < 256);
                out.write(b);
            }
        }

    }

    /* Saves an interesting input to the queue. */
    protected void saveCurrentInput(CodeCoverage runCoverage, Set<Object> responsibilities, String why) throws IOException {

        // First, save to disk (note: we issue IDs to everyone, but only write to disk  if valid)
        int newInputIdx = numSavedInputs++;
        String saveFileName = String.format("id_%06d", newInputIdx);
        String how = currentInput.desc;
        File saveFile = new File(savedCorpusDirectory, saveFileName);
        writeCurrentInputToFile(saveFile);
        log.info("Saved - {} {} {}", saveFile.getPath(), how, why);

        // Second, save to queue
        savedInputs.add(currentInput);

        // Third, store basic book-keeping data
        currentInput.id = newInputIdx;
        currentInput.saveFile = saveFile;
        /* disable it due to memory waste */
        // currentInput.coverage = new CodeCoverage(runCoverage);
        currentInput.hitCoverage = runCoverage.getHitCount();
        currentInput.offspring = 0;
        savedInputs.get(currentParentInputIdx).offspring += 1;

        // Fourth, assume responsibility for branches
        currentInput.responsibilities = responsibilities;
        for (Object b : responsibilities) {
            // If there is an old input that is responsible,
            // subsume it
            Input oldResponsible = responsibleInputs.get(b);
            if (oldResponsible != null) {
                oldResponsible.responsibilities.remove(b);
                // infoLog("-- Stealing responsibility for %s from input %d", b, oldResponsible.id);
            } else {
                // infoLog("-- Assuming new responsibility for %s", b);
            }
            // We are now responsible
            responsibleInputs.put(b, currentInput);
        }
    }

    private void start(Collection<Input> inputs) {
        if (isStarted)
            return;

        for (Input input : seedInputs)
            input.gc();
        seedInputs.clear();

        for (Input input : savedInputs)
            input.gc();
        savedInputs.clear();

        seedInputs.addAll(inputs);
        wholeCoverage = new CodeCoverage();
        totalCoverage = new CodeCoverage();
        validCoverage = new CodeCoverage();
        ccg = new CoverageGuidance();

        numSavedInputs = 0;
        numTrials = 0;
        numValid = 0;
        numError = 0;
        numUniqueError = 0;
        maxCoverage = 0;
        isStarted = true;
    }

    private void start(String seedRandomStr) throws IOException {
        start(Collections.singletonList(new SeedInput(seedRandomStr)));
    }

    private void start(Input input) throws IOException {
        if (input instanceof SeedInput) {
            start(Collections.singletonList(new SeedInput((SeedInput) input)));
        }
    }

    @Override
    public void addSeeds(Collection<FuzzAction> fuzzActions) {
        List<Input> seedInputs = fuzzActions.stream()
                .filter(k -> k.getContent() instanceof FuzzActionIntentContent)
                .map(k -> ((FuzzActionIntentContent) k.getContent()).getIntentInput())
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        start(seedInputs);
    }

    /**
     * A candidate or saved test input that maps objects of type K to bytes.
     */
    public static abstract class Input<K> implements Iterable<Integer> {

        /**
         * The file where this input is saved.
         *
         * <p>This field is null for inputs that are not saved.</p>
         */
        File saveFile = null;

        /**
         * An ID for a saved input.
         *
         * <p>This field is -1 for inputs that are not saved.</p>
         */
        int id;

        /**
         * The description for this input.
         *
         * <p>This field is modified by the construction and mutation
         * operations.</p>
         */
        String desc;

        /**
         * The run coverage for this input, if the input is saved.
         *
         * <p>This field is null for inputs that are not saved.</p>
         */
        CodeCoverage coverage = null;

        /**
         * The number of non-zero elements in `coverage`.
         *
         * <p>This field is -1 for inputs that are not saved.</p>
         *
         * <p></p>When this field is non-negative, the information is
         * redundant (can be computed using {@link CodeCoverage#getHitCount()}),
         * but we store it here for performance reasons.</p>
         */
        int hitCoverage = -1;

        /**
         * The number of mutant children spawned from this input that
         * were saved.
         *
         * <p>This field is -1 for inputs that are not saved.</p>
         */
        int offspring = -1;

        /**
         * Whether this input resulted in a valid run.
         */
        boolean valid = false;

        /**
         * The set of coverage keys for which this input is
         * responsible.
         *
         * <p>This field is null for inputs that are not saved.</p>
         *
         * <p>Each coverage key appears in the responsibility set
         * of exactly one saved input, and all covered keys appear
         * in at least some responsibility set. Hence, this list
         * needs to be kept in-sync with {@link #responsibleInputs}.</p>
         */
        Set<Object> responsibilities = null;


        /**
         * Create an empty input.
         */
        public Input() {
            desc = "random";
        }

        /**
         * Create a copy of an existing input.
         *
         * @param toClone the input map to clone
         */
        public Input(Input toClone) {
            desc = String.format("src:%06d", toClone.id);
        }

        public abstract int getOrGenerateFresh(K key, Random random);
        public abstract int size();
        public abstract Input fuzz(Random random);
        public abstract void gc();



        /**
         * Returns whether this input should be favored for fuzzing.
         *
         * <p>An input is favored if it is responsible for covering
         * at least one branch.</p>
         *
         * @return whether or not this input is favored
         */
        public boolean isFavored() {
            return responsibilities.size() > 0;
        }


        /**
         * Sample from a geometric distribution with given mean.
         *
         * Utility method used in implementing mutation operations.
         *
         * @param random a pseudo-random number generator
         * @param mean the mean of the distribution
         * @return a randomly sampled value
         */
        public static int sampleGeometric(Random random, double mean) {
            double p = 1 / mean;
            double uniform = random.nextDouble();
            return (int) ceil(log(1 - uniform) / log(1 - p));
        }
    }

    public static class LinearInput extends Input<Integer> {

        /** A list of byte values (0-255) ordered by their index. */
        protected ArrayList<Integer> values;

        /** The number of bytes requested so far */
        protected int requested = 0;

        public LinearInput() {
            super();
            this.values = new ArrayList<>();
        }

        public LinearInput(LinearInput other) {
            super(other);
            this.values = new ArrayList<>(other.values);
        }


        @Override
        public int getOrGenerateFresh(Integer key, Random random) {
            // Otherwise, make sure we are requesting just beyond the end-of-list
            // assert (key == values.size());
            if (key != requested) {
                throw new IllegalStateException(String.format("Bytes from linear input out of order. " +
                        "Size = %d, Key = %d", values.size(), key));
            }

            // Don't generate over the limit
            if (requested >= ZestIntentGuidanceConfigs.MAX_INPUT_SIZE) {
                return -1;
            }

            // If it exists in the list, return it
            if (key < values.size()) {
                requested++;
                // infoLog("Returning old byte at key=%d, total requested=%d", key, requested);
                return values.get(key);
            }

            // Just generate a random input
            int val = random.nextInt(256);
            values.add(val);
            requested++;
            // infoLog("Generating fresh byte at key=%d, total requested=%d", key, requested);
            return val;
        }

        @Override
        public int size() {
            return values.size();
        }

        /**
         * Truncates the input list to remove values that were never actually requested.
         *
         * <p>Although this operation mutates the underlying object, the effect should
         * not be externally visible (at least as long as the test executions are
         * deterministic).</p>
         */
        @Override
        public void gc() {
            // Remove elements beyond "requested"
            values = new ArrayList<>(values.subList(0, requested));
            values.trimToSize();
        }

        @Override
        public Input fuzz(Random random) {
            // Clone this input to create initial version of new child
            LinearInput newInput = new LinearInput(this);

            // Stack a bunch of mutations
            int numMutations = sampleGeometric(random, ZestIntentGuidanceConfigs.MEAN_MUTATION_COUNT);
            newInput.desc += ",havoc:"+numMutations;

            boolean setToZero = random.nextDouble() < 0.1; // one out of 10 times

            for (int mutation = 1; mutation <= numMutations; mutation++) {

                // Select a random offset and size
                int offset = random.nextInt(newInput.values.size());
                int mutationSize = sampleGeometric(random, ZestIntentGuidanceConfigs.MEAN_MUTATION_SIZE);

                // desc += String.format(":%d@%d", mutationSize, idx);

                // Mutate a contiguous set of bytes from offset
                for (int i = offset; i < offset + mutationSize; i++) {
                    // Don't go past end of list
                    if (i >= newInput.values.size()) {
                        break;
                    }

                    // Otherwise, apply a random mutation
                    int mutatedValue = setToZero ? 0 : random.nextInt(256);
                    newInput.values.set(i, mutatedValue);
                }
            }

            return newInput;
        }

        @Override
        public Iterator<Integer> iterator() {
            return values.iterator();
        }
    }

    public static class SeedInput extends LinearInput {
        File seedFile;
        String seedString;
        byte[] bytes;
        final InputStream in;

        public SeedInput(File seedFile) throws IOException {
            super();
            this.seedFile = seedFile;
            this.in = new BufferedInputStream(new FileInputStream(seedFile));
            this.desc = "seed";
        }

        public SeedInput(String seedString) throws IOException {
            super();
            this.seedString = seedString;
            this.in = new ByteArrayInputStream(seedString.getBytes(StandardCharsets.UTF_8));
            this.desc = "seed";
        }

        public SeedInput(ByteArrayOutputStream outputStream) throws IOException {
            super();
            this.bytes = outputStream.toByteArray();
            this.in = new ByteArrayInputStream(bytes);
            this.desc = "seed";
        }

        public SeedInput(byte[] bytes) {
            super();
            this.bytes = bytes;
            this.in = new ByteArrayInputStream(bytes);
            this.desc = "seed";
        }

        public SeedInput(SeedInput seedInput) throws IOException {
            super();
            if (seedInput.seedFile != null) {
                this.seedFile = seedInput.seedFile;
                this.in = new BufferedInputStream(new FileInputStream(seedFile));

            } else if (seedInput.seedString != null) {
                this.seedString = seedInput.seedString;
                this.in = new ByteArrayInputStream(seedString.getBytes(StandardCharsets.UTF_8));

            } else {
                bytes = Arrays.copyOf(seedInput.bytes, seedInput.bytes.length);
                this.in = new ByteArrayInputStream(bytes);
            }
            this.desc = "seed-gen";
        }

        @Override
        public int getOrGenerateFresh(Integer key, Random random) {
            int value;
            try {
                value = in.read();
            } catch (IOException e) {
                if (seedFile != null)
                    throw new GuidanceException("Error reading from seed file: " + seedFile.getName(), e);
                else
                    throw new GuidanceException("Error reading from byte array ", e);
            }

            // assert (key == values.size())
            if (key != values.size()) {
                throw new IllegalStateException(String.format("Bytes from seed out of order. " +
                        "Size = %d, Key = %d", values.size(), key));
            }

            if (value >= 0) {
                requested++;
                values.add(value);
            }

            // If value is -1, then it is returned (as EOF) but not added to the list
            return value;
        }

        @Override
        public void gc() {
            super.gc();
            try {
                in.close();
            } catch (IOException e) {
                throw new GuidanceException("Error closing seed file:" + seedFile.getName(), e);
            }
        }
    }
}
