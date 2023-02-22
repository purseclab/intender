package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api;

import com.pholser.junit.quickcheck.internal.Ranges;
import com.pholser.junit.quickcheck.internal.Ranges.Type;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

import java.util.Random;

/**
 * A source of randomness with better performance but looser
 * statistical guarantees.
 *
 * This class is meant for use with guided fuzzing, where the
 * {@link Random} delegate is usually a {@link StreamBackedRandom}.
 * In this case, the random source does not have to give any
 * statistical guarantees such as uniformity or independentness,
 * and therefore is amenable to several optimizations, which are
 * implemented in this class.
 *
 * @author Rohan Padhye
 */
public class FastSourceOfRandomness extends SourceOfRandomness {

    private StreamBackedRandom delegate;

    public FastSourceOfRandomness(StreamBackedRandom delegate) {
        super(delegate);
        // Gotta make a copy of the reference because
        // super-class declares the field as private :-\
        this.delegate = delegate;
    }

    @Override
    public Random toJDKRandom() {
        return this.delegate;
    }

    @Override
    public byte nextByte(byte min, byte max) {
        if (min == Byte.MIN_VALUE && max == Byte.MAX_VALUE) {
            return delegate.nextByte();
        } else if (min >= Byte.MIN_VALUE && max <= Byte.MAX_VALUE) {

        }
        return this.fastChooseByteInRange(min, max);
    }

    @Override
    public short nextShort(short min, short max) {
        if (min == Short.MIN_VALUE && max == Short.MAX_VALUE) {
            return delegate.nextShort();
        }
        return (short)(this.fastChooseIntInRange(min, max));
    }

    @Override
    public char nextChar(char min, char max) {
        Ranges.checkRange(Type.CHARACTER, min, max);
        return (char)(this.fastChooseIntInRange(min, max));

    }

    @Override
    public int nextInt(int min, int max) {
        if (min == Integer.MIN_VALUE && max == Integer.MAX_VALUE) {
            return delegate.nextInt();
        }

        return this.fastChooseIntInRange(min, max);
    }

    @Override
    public long nextLong(long min, long max) {
        int comparison = Ranges.checkRange(Type.INTEGRAL, min, max);

        if (min == Long.MIN_VALUE && max == Long.MAX_VALUE) {
            return delegate.nextLong();
        }

        return comparison == 0 ? min : Ranges.choose(this, min, max);
    }

    private int fastChooseIntInRange(int min, int max) {
        int range = max - min;

        // If range is too wide, overflow will make it negative
        if (range > 0) {
            int random = delegate.nextInt() % range;
            if (random < 0) {
                random += range;
            }
            return min + random;
        } else {
            return (int) Ranges.choose(this, min, max);
        }
    }

    private byte fastChooseByteInRange(byte min, byte max) {
        int range = max - min;

        // If range is too wide, overflow will make it negative
        if (range > 0 && range <= (Byte.MAX_VALUE)) {
            int random = delegate.nextByte() % range;
            if (random < 0) {
                random += range;
            }
            byte result = (byte) (min + random);
            assert (result >= min && result <= max);
            return result;
        } else {
            return (byte) fastChooseIntInRange((int) min, (int) max);
        }
    }

}
