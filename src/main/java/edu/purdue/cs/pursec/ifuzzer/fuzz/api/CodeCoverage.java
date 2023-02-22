package edu.purdue.cs.pursec.ifuzzer.fuzz.api;

import com.sun.tools.javac.jvm.Code;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import org.jacoco.core.analysis.*;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.data.ExecutionDataStore;
import org.jacoco.core.data.SessionInfo;
import org.jacoco.core.data.SessionInfoStore;
import org.jacoco.core.tools.ExecFileLoader;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

public class CodeCoverage {
    private final static int BRANCH_HIT_IDX    = 0;
    private final static int BRANCH_ALL_IDX    = 1;
    private final static int INST_HIT_IDX      = 2;
    private final static int INST_ALL_IDX      = 3;

    private ExecFileLoader loader;
//    private byte[] globalTraceBits = new byte[ConfigConstants.COVERAGE_MAP_SIZE];
    private byte[] traceBits = new byte[ConfigConstants.COVERAGE_MAP_SIZE];
    // branch covered, branch total, inst covered, inst total
//    private Map<String, List<Integer>> globalCountersPerMethod;
    private int[] interstingCnt = new int[4];
    private int[][] semanticCnt = new int[ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS][4];
    private int totalCnt, hitCnt;
    private boolean isAnalyzed;

    public CodeCoverage() {}

    public CodeCoverage(CodeCoverage coverage) {
//        globalTraceBits[0] = 1;
//        for (int i = 1; i < ConfigConstants.COVERAGE_MAP_SIZE; i++)
//            globalTraceBits[i] = 0;

        this.updateCoverage(coverage);
    }

    public void applyLoader(ExecFileLoader loader) {
        this.loader = loader;
        if (traceBits[0] > 0) {
            totalCnt = 0;
            hitCnt = 0;
            traceBits = new byte[ConfigConstants.COVERAGE_MAP_SIZE];
            interstingCnt = new int[4];
            semanticCnt = new int[ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS][4];
        }

        analyze(loader);
        this.isAnalyzed = true;
    }

    public byte[] getTraceBits() {
        return this.traceBits;
    }

    public boolean updateCoverage(CodeCoverage that) {
        boolean changed = false;

        if (this.loader == null) {
            this.loader = that.loader;
        } else {
            ExecutionDataStore dataStore = this.loader.getExecutionDataStore();
            SessionInfoStore infoStore = this.loader.getSessionInfoStore();

            that.loader.getExecutionDataStore().getContents().forEach(dataStore::put);
            that.loader.getSessionInfoStore().getInfos().forEach(infoStore::visitSessionInfo);
        }

        this.traceBits[0] = 1;
        for (int i = 1; i < ConfigConstants.COVERAGE_MAP_SIZE; i++) {
            int before = this.traceBits[i];
            this.traceBits[i] |= Integer.highestOneBit(that.traceBits[i]);

            if (!changed && before != this.traceBits[i]) {
                changed = true;
            }
        }

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS; j++) {
                this.semanticCnt[j][i] = Integer.max(this.semanticCnt[j][i], that.semanticCnt[j][i]);
            }
            this.interstingCnt[i] = Integer.max(this.interstingCnt[i], that.interstingCnt[i]);
        }

        return changed;
    }

    public void diffCoverage(CodeCoverage that) {
        if (this.loader == null) {
            this.loader = that.loader;
            analyze(this.loader);
        } else {
            ExecutionDataStore dataStore = this.loader.getExecutionDataStore();
            SessionInfoStore infoStore = this.loader.getSessionInfoStore();

            for (ExecutionData data : dataStore.getContents()) {
                if (!that.loader.getExecutionDataStore().contains(data.getName())) {
                    dataStore.subtract(data);
                }
            }

            // XXX: fix it
            that.loader.getSessionInfoStore().getInfos().forEach(infoStore::visitSessionInfo);
        }
    }

    public Collection<?> computeNewCoverage(CodeCoverage baseline) {
        Collection<Integer> newCoverage = new ArrayList<>();
        for (int i = 1; i < ConfigConstants.COVERAGE_MAP_SIZE; i++) {
            if (this.traceBits[i] > 0 && baseline.traceBits[i] == 0)
                newCoverage.add(i);
        }

        return newCoverage;
    }

    public int getHitCount() {
        int hitCount = 0;
        for (int i = 1; i < ConfigConstants.COVERAGE_MAP_SIZE; i++) {
            if (this.traceBits[i] != 0)
                hitCount ++;
        }

        return hitCount;
    }

    public int getBranchHitCount() {
        return interstingCnt[BRANCH_HIT_IDX];
    }

    public int getInstructionHitCount() {
        return interstingCnt[INST_HIT_IDX];
    }

    public ExecFileLoader getLoader() {
        return loader;
    }

    public void putBitmap(ByteBuffer buf) {
        buf.put(traceBits);
    }

    public static String getProportionStatsHeader() {
        StringBuilder builder = new StringBuilder();
        builder.append("# time(ms), totalHit%, Hit%, covered1(all%, br%, inst%), ..., covered7, etc.\n");
        return builder.toString();
    }

    public static String getStatsHeader() {
        StringBuilder builder = new StringBuilder();
        builder.append("# time(ms), hit, total, interesting(branchHit, branchAll, instHit, instAll), covered1, ..., covered7, covered0");
        return builder.toString();
    }

    public String getProportionStatsString() {

        StringBuilder builder = new StringBuilder();
        builder.append(System.currentTimeMillis());
        builder.append(", ");
        builder.append((hitCnt * 100.0f) / totalCnt);
        builder.append("%, ");
        builder.append(((interstingCnt[BRANCH_HIT_IDX] + interstingCnt[INST_HIT_IDX]) * 100.0f)
                / (interstingCnt[BRANCH_ALL_IDX] + interstingCnt[INST_ALL_IDX]));
        builder.append("%, ");
        builder.append(((interstingCnt[BRANCH_HIT_IDX]) * 100.0f) / interstingCnt[BRANCH_ALL_IDX]);
        builder.append("%, ");
        builder.append(((interstingCnt[INST_HIT_IDX]) * 100.0f) / interstingCnt[INST_ALL_IDX]);
        builder.append("%");
        for (int i = 1; i <= ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS; i++) {
            int idx = i % ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS;
            builder.append(", ");
            builder.append(((semanticCnt[idx][BRANCH_HIT_IDX] + semanticCnt[idx][INST_HIT_IDX]) * 100.0f)
                    / (semanticCnt[idx][BRANCH_ALL_IDX] + semanticCnt[idx][INST_ALL_IDX]));
            builder.append("%, ");
            builder.append((semanticCnt[idx][BRANCH_HIT_IDX] * 100.0f) / semanticCnt[idx][BRANCH_ALL_IDX]);
            builder.append("%, ");
            builder.append((semanticCnt[idx][INST_HIT_IDX] * 100.0f) / semanticCnt[idx][INST_ALL_IDX]);
            builder.append("%");
        }
        return builder.toString();
    }

    public String getStatsString() {
        return getStatsString(true);
    }

    public String getStatsString(boolean printTime) {
        StringBuilder builder = new StringBuilder();
        if (printTime) {
            builder.append(System.currentTimeMillis());
            builder.append(", ");
        }
        builder.append(hitCnt);
        builder.append(", ");
        builder.append(totalCnt);

        for (int i = 0; i < 4; i++) {
            builder.append(", ");
            builder.append(interstingCnt[i]);
        }

        for (int i = 1; i <= ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS; i++) {
            for (int j = 0; j < 4; j++) {
                builder.append(", ");
                builder.append(semanticCnt[i % ConfigConstants.CONFIG_NUM_CODE_SEMANTIC_LEVELS][j]);
            }
        }
        return builder.toString();
    }

    private int getSemanticLevel(String className) {
        if (IFuzzer.classSemanticMap == null)
            return 0;

        String matchedPackage = "";
        for (String pkg : IFuzzer.classSemanticMap.keySet()) {
            if (className.startsWith(pkg + "/") &&
                    pkg.length() > matchedPackage.length()) {
                matchedPackage = pkg;
            }
        }

        return IFuzzer.classSemanticMap.getOrDefault(matchedPackage, 0);
    }

    /**
     *
     * @param methodKey: "class: name(args,...)return"
     * @return
     */
    private int getSemanticLevelFromMethodKey(String methodKey) {
        return getSemanticLevel(methodKey.split(":")[0]);
    }

    private void analyze(ExecFileLoader loader) {

        // Fill tracebits
        traceBits[0] = 1;
        for (int i = 1; i < ConfigConstants.COVERAGE_MAP_SIZE; i++)
            traceBits[i] = 0;

        boolean analyzeClassOnly = true;

        // Class-aware Coverage
        if (IFuzzer.classfiles != null && IFuzzer.methodBitmap != null && IFuzzer.classpathMap != null) {
            analyzeClassOnly = false;

            try {
                /* Analyze */
                final CoverageBuilder builder = new CoverageBuilder();
                final Analyzer analyzer = new Analyzer(loader.getExecutionDataStore(), builder);

                Set<String> analyzedPath = new HashSet<>();
                for (ExecutionData data : loader.getExecutionDataStore().getContents()) {
                    // Skip classes which are not interesting
                    String path = IFuzzer.classpathMap.get(data.getName());
                    if (path != null && path.length() > 0 && !analyzedPath.contains(path)) {
//                        System.out.printf("### analyze %s(%s)\n", data.getName(), path);
                        analyzer.analyzeAll(new File(path));
                        analyzedPath.add(path);
                    }
                }

                final IBundleCoverage bundle = builder.getBundle("sample");
                int methodCnt = 0, classCnt = 0;

                /* fill coverageMap */
                for (IPackageCoverage packageCoverage : bundle.getPackages()) {
                    for (IClassCoverage classCoverage : packageCoverage.getClasses()) {

                        if (classCoverage.getName() == null)
                            continue;

                        int lvl = getSemanticLevel(classCoverage.getName());

                        // Calculate semantic counter (class-level)
                        semanticCnt[lvl][BRANCH_HIT_IDX] += classCoverage.getBranchCounter().getCoveredCount();
                        semanticCnt[lvl][BRANCH_ALL_IDX] += classCoverage.getBranchCounter().getTotalCount();
                        semanticCnt[lvl][INST_HIT_IDX] += classCoverage.getInstructionCounter().getCoveredCount();
                        semanticCnt[lvl][INST_ALL_IDX] += classCoverage.getInstructionCounter().getTotalCount();

                        if (lvl == 0 && ConfigConstants.CONFIG_ENABLE_CODE_COVERAGE_FILTER)
                            continue;

                        classCnt ++;

                        // Get counter per method
                        for (IMethodCoverage methodCoverage : classCoverage.getMethods()) {
                            int covered = methodCoverage.getBranchCounter().getCoveredCount() +
                                    methodCoverage.getInstructionCounter().getCoveredCount();

                            if (methodCoverage.getName() == null)
                                continue;

                            methodCnt ++;

                            String key = JavaNames.getKeyFromMethod(classCoverage.getName(),
                                    methodCoverage.getName(), methodCoverage.getDesc());

                            /* fill bitmap */
                            int hashId = JavaNames.getHash(key, ConfigConstants.COVERAGE_MAP_SIZE);
                            if (IFuzzer.methodBitmap[hashId]) {
                                traceBits[hashId] += covered;
                                // Calculate interesting counter in method-level
                                interstingCnt[BRANCH_HIT_IDX] += methodCoverage.getBranchCounter().getCoveredCount();
                                interstingCnt[BRANCH_ALL_IDX] += methodCoverage.getBranchCounter().getTotalCount();
                                interstingCnt[INST_HIT_IDX] += methodCoverage.getInstructionCounter().getCoveredCount();
                                interstingCnt[INST_ALL_IDX] += methodCoverage.getInstructionCounter().getTotalCount();
                            }
                        }
                    }
                }

                System.out.printf("[INFO] %d classes & %d methods\n", classCnt, methodCnt);

            } catch (IOException e) {
                e.printStackTrace();
                analyzeClassOnly = true;
            }
        }

        int localTotalCnt = 0;
        int localHitCnt = 0;

        for (ExecutionData data : loader.getExecutionDataStore().getContents()) {

            // Skip classes which are not interesting
            if (IFuzzer.classpathMap != null) {
                if (IFuzzer.classpathMap.get(data.getName()) == null)
                    continue;
            }

            int feedbackId = JavaNames.getHash(data.getId(), ConfigConstants.COVERAGE_MAP_SIZE);

            for (boolean probe : data.getProbes()) {
                if (probe) {
                    if (analyzeClassOnly)
                        traceBits[feedbackId]++;
                    localHitCnt ++;
                }
            }
            localTotalCnt += data.getProbes().length;
        }

        if (hitCnt < localHitCnt)
            hitCnt = localHitCnt;

        if (totalCnt < localTotalCnt)
            totalCnt = localTotalCnt;

//        for (int i = 0; i < ConfigConstants.COVERAGE_MAP_SIZE; i++) {
//            if (globalTraceBits[i] < traceBits[i])
//                globalTraceBits[i] = traceBits[i];
//        }
    }
}
