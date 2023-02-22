package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api;

public class ZestIntentGuidanceConfigs {
    public static final boolean CONFIG_ENABLE_INTENT_FORMATTED_GEN = true;

    /** Max input size to generate. */
    public static final int MAX_INPUT_SIZE = Integer.getInteger("intender.ei.MAX_INPUT_SIZE", 10240);

    /** Mean number of mutations to perform in each round. */
    public static final double MEAN_MUTATION_COUNT = 8.0;

    /** Mean number of contiguous bytes to mutate in each mutation. */
    public static final double MEAN_MUTATION_SIZE = 4.0; // Bytes

    /** Baseline number of mutated children to produce from a given parent input. */
    public static final int NUM_CHILDREN_BASELINE = 50;

    /** Multiplication factor for number of children to produce for favored inputs. */
    public static final int NUM_CHILDREN_MULTIPLIER_FAVORED = 20;
}
