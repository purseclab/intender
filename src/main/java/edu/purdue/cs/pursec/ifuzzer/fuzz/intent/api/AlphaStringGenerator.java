package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api;

import com.pholser.junit.quickcheck.generator.java.lang.AbstractStringGenerator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class AlphaStringGenerator extends AbstractStringGenerator {

    @Override
    protected int nextCodePoint(SourceOfRandomness sourceOfRandomness) {
        int randomIndex = sourceOfRandomness.nextInt(52);
        if (randomIndex < 26) {
            return 'a' + randomIndex;
        } else {
            return 'A' + randomIndex - 26;
        }
    }

    @Override
    protected boolean codePointInRange(int i) {
        if (i >= 'a' && i <= 'z')
            return true;
        if (i >= 'A' && i <= 'Z')
            return true;
        return false;
    }
}
