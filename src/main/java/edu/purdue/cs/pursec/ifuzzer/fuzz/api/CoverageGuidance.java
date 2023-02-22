package edu.purdue.cs.pursec.ifuzzer.fuzz.api;

import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import java.nio.ByteBuffer;
import java.util.Arrays;

// reflects AFL
public class CoverageGuidance {
    private byte[] virginCover = new byte[ConfigConstants.COVERAGE_MAP_SIZE];
    private byte[] virginCrash = new byte[ConfigConstants.COVERAGE_MAP_SIZE];

    public CoverageGuidance () {
        Arrays.fill(virginCover, (byte) 0xff);
        Arrays.fill(virginCrash, (byte) 0xff);
    }

    private int hasNewBits(byte[] traceBits, byte[] virginBits) {
        int hnb = 0;
        ByteBuffer traceBuf = ByteBuffer.wrap(traceBits);
        ByteBuffer virginBuf = ByteBuffer.wrap(virginBits);

        for (int i = 0; i < ConfigConstants.COVERAGE_MAP_SIZE; i += 4) {
            int traceRaw = traceBuf.getInt(i);
            int virginRaw = virginBuf.getInt(i);
            if (traceRaw > 0 && (traceRaw & virginRaw) > 0) {
                for (int j = i; j < i + 4; j++) {
                    if (hnb < 2) {
                        if (traceBits[j] > 0 && virginBits[j] == (byte) 0xff)
                            hnb = 2;
                        else
                            hnb = 1;
                    }
                    virginBits[j] &= ~traceBits[j];
                }
            }
        }
        return hnb;
    }

    public int isUniqueCrash(CodeCoverage coverage) {
        return hasNewBits(coverage.getTraceBits(), this.virginCrash);
    }

    public int hasNewBits(CodeCoverage coverage) {
        return hasNewBits(coverage.getTraceBits(), this.virginCover);
    }
}
