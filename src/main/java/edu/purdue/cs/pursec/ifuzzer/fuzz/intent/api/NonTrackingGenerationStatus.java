package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.internal.GeometricDistribution;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Provides a generation status that does not track the number of trials
 * generated so far. This is useful for guided fuzzing where the burden
 * of making choices is on the guidance system rather than on quickcheck.
 *
 * @author Rohan Padhye
 */
public class NonTrackingGenerationStatus implements GenerationStatus {

    public static final int MEAN_SIZE = 10;

    private final SourceOfRandomness random;
    private final Map<Key<?>, Object> contextValues = new HashMap<>();
    private final GeometricDistribution geometric = new GeometricDistribution();


    public NonTrackingGenerationStatus(SourceOfRandomness random) {
        this.random = random;
    }

    @Override
    public int size() {
        return geometric.sampleWithMean(MEAN_SIZE, random);
    }

    @Override
    public int attempts() {
        throw new UnsupportedOperationException("attempts() and @ValueOf" +
                " is not supported in guided mode.");
    }

    @Override
    public <T> GenerationStatus setValue(Key<T> key, T value) {
        contextValues.put(key, value);
        return this;
    }

    @Override
    public <T> Optional<T> valueOf(Key<T> key) {
        return Optional.ofNullable(key.cast(contextValues.get(key)));
    }
}
