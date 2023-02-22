package edu.purdue.cs.pursec.ifuzzer.fuzz.api;

import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

public class IntentStateCoverage {
    /*
     * It should have
     * 1) operation (add/mod/withdraw/purge/add-link/add-host/del-link/del-host)
     * 2) intent-state transition (e.g. INN, NFN, NII)
     * 3) (optional) intent-data transition
     * for each entry.
     *
     * Also, it could be comparable (e.g. branchHitCount of coverage.)
     */
    private static Logger log = LoggerFactory.getLogger(IntentStateCoverage.class);

    private static final byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
    public static final byte ADD_INTENT_OPER                = 0;
    public static final byte MOD_INTENT_OPER                = 1;
    public static final byte WITHDRAW_INTENT_OPER           = 2;
    public static final byte PURGE_INTENT_OPER              = 3;
    public static final byte ADD_LINK_OPER                  = 4;
    public static final byte ADD_HOST_OPER                  = 5;
    public static final byte ADD_DEVICE_OPER                = 6;
    public static final byte DEL_LINK_OPER                  = 7;
    public static final byte DEL_HOST_OPER                  = 8;
    public static final byte DEL_DEVICE_OPER                = 9;
    public static final byte CP_VERIFY_OPER                 = 10;
    public static final byte DP_VERIFY_OPER                 = 11;
    public static final byte MAX_OPER                       = 12;
    private static final boolean[] hasSingleMember = {false, true, true, true,
            false, false, false, false, false, false, true, true};
    private static final String[] operToCmd = {"add-intent", "mod-intent", "withdraw-intent", "purge-intent",
            "add-link", "add-host", "add-device", "delete-link", "delete-host", "delete-device", "cp-verify-intent", "dp-verify-intent"};

    List<IntentStateTransitionEntry> entries = new LinkedList<>();
    Map<String, Intent.State> globalIntentState = new HashMap<>();

    List<String> appliedIntents = new LinkedList<>();

    /* Temporary cache for add-intent */
    Map<Integer, List<String>> cacheReqIntentSortedMap = new TreeMap<>();
    Map<String, Intent.State> cacheReqIntents = new HashMap<>();
    int[] numOperations = new int[MAX_OPER];

    Map<String, Integer> intentStateChanges = new HashMap<>();
    int intentStateChangeCnt;

    public IntentStateCoverage() {
    }

    public void updateCoverage(IntentStateCoverage coverage) {
        // TODO: manage intent state transitions

        // append numOperations
        for (byte i = 0; i < MAX_OPER; i++) {
            this.numOperations[i] += coverage.numOperations[i];
        }
    }

    private int getIdx(String intentKey) {
        int idx = 0;
        for (String key : appliedIntents) {
            if (key.equals(intentKey))
                return idx;
            idx ++;
        }

        // Not found
        return -1;
    }

    private int applyCachedReqIntents() {
        if (cacheReqIntents.size() == 0)
            return 0;

        // 1. Convert cacheSortedMap to Ordered List
        List<String> newIntents = new ArrayList<>();
        for (Map.Entry<Integer, List<String>> entry : cacheReqIntentSortedMap.entrySet()) {
            List<String> installedIntents = new ArrayList<>();
            List<String> failedIntents =  new ArrayList<>();
            List<String> exceptionalIntents = new ArrayList<>();
            for (String key : entry.getValue()) {
                if (State.INSTALLED.equals(cacheReqIntents.get(key))) {
                    installedIntents.add(key);
                } else if (State.FAILED.equals(cacheReqIntents.get(key))) {
                    failedIntents.add(key);
                } else {
                    exceptionalIntents.add(key);
                }
            }

            // For same priority, I,I,I then F,F,...
            newIntents.addAll(installedIntents);
            newIntents.addAll(failedIntents);
            newIntents.addAll(exceptionalIntents);

            // clear list only
            entry.getValue().clear();
        }

        // 2. store ordered-list into appliedIntents
        appliedIntents.addAll(newIntents);

        // create entry
        entries.add(new IntentStateTransitionEntry(ADD_INTENT_OPER,
                newIntents.stream().map(k -> cacheReqIntents.get(k)).collect(Collectors.toList())));

        intentStateChanges.put("add-intent", intentStateChanges.getOrDefault("add-intent", 0) +
                newIntents.size());
        intentStateChangeCnt += newIntents.size();

        // clear cache
        cacheReqIntents.clear();

        return newIntents.size();
    }

    private byte cmdToByteOper(String cmd) {
        if (cmd.endsWith("device"))
            return -1;

        for (byte i = 0; i < operToCmd.length; i++) {
            if (cmd.equals(operToCmd[i]))
                return i;
        }

        log.warn("unknown cmd: {}", cmd);
        return -1;
    }

    public byte[] toByteArray() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        entries.forEach(k -> {
            try {
                outputStream.write(k.toByteArray());
            } catch (IOException e) {
                e.printStackTrace();
            }
        });

        return outputStream.toByteArray();
    }

//    public byte[] toByteArray() {
//        // oper|isError|hasIdx(1B) + idx/len (4B) + payload
//        int tmp = oper << 2 | (isError ? 1 : 0) | (idx < 0 ? 0 : 1);
//        ByteBuffer byteBuffer;
//
//        if (idx >= 0) {
//            byteBuffer = ByteBuffer.allocate(5 + this.len)
//                    .put((byte) tmp)
//                    .putInt(idx)
//                    .put(state);
//        } else if (len > 0) {
//            byteBuffer = ByteBuffer.allocate(5 + this.len)
//                    .put((byte) tmp)
//                    .putInt(len)
//                    .put(state);
//        } else {
//            // len == 0 && idx < 0
//            byteBuffer = ByteBuffer.allocate(1)
//                    .put((byte) tmp);
//        }
//
//        return byteBuffer.array();
//    }

    public static String toStringFromByteArray(byte[] bytes) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            int oper = bytes[i];
            boolean isError = false;
            if ((oper & 0x2) > 0)
                isError = true;

            boolean hasIdx = false;
            if ((oper & 0x1) > 0) {
                // has Idx
                hasIdx = true;
            }

            // 1. Is error?
            if (isError)
                builder.append("[ERR] ");

            // 2. command
            builder.append(operToCmd[(oper >> 2)]);

            if (isError && !hasIdx) {
                builder.append("\n");
                continue;
            }

            byte[] tmp = new byte[4];
            for (int j = 0; j < 4; j++) {
                tmp[j] = bytes[++i];
            }

            int idx;
            int len;
            if (hasIdx) {
                idx = ByteBuffer.wrap(tmp).getInt();
                len = 1;
            } else {
                idx = -1;
                len = ByteBuffer.wrap(tmp).getInt();
            }

            // 3. get all states
            if (len > 0)
                builder.append(": ");
            for (int j = 0; j < len; j++)
                builder.append(State.shortStateFromByteCode(bytes[++i]));

            // 4. define index
            if (idx >= 0)
                builder.append(" @ ").append(idx);

            builder.append("\n");
        }

        return builder.toString();
    }

    public String toHexString() {
        byte[] bytes = this.toByteArray();
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars, StandardCharsets.UTF_8);
    }

    public int getIntentStateChangeCnt() {
        return this.intentStateChangeCnt;
    }

    public int[] getNumOperations() {
        return numOperations;
    }

    public byte logAction(FuzzAction fuzzAction) {
        byte operCode = cmdToByteOper(fuzzAction.getActionCmd());
        if (operCode >= 0)
            numOperations[operCode] ++;

        return operCode;
    }

    public void applyAction(FuzzAction fuzzAction, Object retObject) {
        // TODO: log error action
        String actionCmd = fuzzAction.getActionCmd();

        if (actionCmd.contains("verify-intent")) {
            log.info("skip recording state: {}", fuzzAction.getActionCmd());
            applyCachedReqIntents();
            return;
        }

        byte operCode = cmdToByteOper(actionCmd);

        if (fuzzAction.isTopoOperation()) {
            if (retObject instanceof List) {

                // If action is error,
                if (fuzzAction.isError()) {
                    applyCachedReqIntents();
                    entries.add(new IntentStateTransitionEntry(operCode, true));
                    return;
                }

                // get operation code
                if (operCode < 0)
                    return;

                // there is no changed intent during topo-change
                if (((List) retObject).size() == 0)
                    return;

                applyCachedReqIntents();

                // init state-code array
                byte[] stateCodes = new byte[appliedIntents.size()];
                for (int i = 0; i < appliedIntents.size(); i++)
                    stateCodes[i] = 0;

                // loop to get all state changes
                for (Object obj : (List) retObject) {
                    if (!(obj instanceof Intent)) {
                        continue;
                    }

                    Intent intent = (Intent) obj;
                    State oldState = globalIntentState.put(intent.getKey(), intent.getState());
                    if (oldState != null && !oldState.equals(intent.getState())) {
                        intentStateChanges.put(actionCmd, intentStateChanges.getOrDefault(actionCmd, 0) + 1);
                        intentStateChangeCnt++;
                    }
                    stateCodes[getIdx(intent.getKey())] = intent.getState().toByteCode();
                }

                entries.add(new IntentStateTransitionEntry(operCode, stateCodes));

            } else {
                // ERROR
                throw new UnsupportedOperationException("topoOperation should return retObject");
            }

        } else {
            Intent intent;
            if (retObject instanceof Intent) {
                intent = (Intent) retObject;
            } else {
                log.warn("####### No retObject for {} ########",
                        fuzzAction.getActionCmd());

                if (fuzzAction.isError()) {
                    applyCachedReqIntents();
                    entries.add(new IntentStateTransitionEntry(operCode, true));
                    return;
                }

                // TODO: async action
                return;
            }

            if (fuzzAction.isError()) {
                applyCachedReqIntents();
                log.warn("Error during {} on {}[{}]", fuzzAction.getActionCmd(),
                        intent.getKey(), getIdx(intent.getKey()));
                entries.add(new IntentStateTransitionEntry(operCode, true, getIdx(intent.getKey()), intent.getState()));
                return;
            }

            if (fuzzAction.getActionCmd().startsWith("add-intent")) {
                // 1. put key list for each priority
                cacheReqIntentSortedMap.computeIfAbsent(intent.getPriority(), k -> new ArrayList<>())
                        .add(intent.getKey());
                cacheReqIntents.put(intent.getKey(), intent.getState());

                // 2. put state for key
                globalIntentState.put(intent.getKey(), intent.getState());

            } else {
                // 1. add temporary intents
                applyCachedReqIntents();
                State oldState;

                if (actionCmd.startsWith("mod-intent")) {
                    entries.add(new IntentStateTransitionEntry(MOD_INTENT_OPER, getIdx(intent.getKey()), intent.getState()));

                    oldState = globalIntentState.put(intent.getKey(), intent.getState());
                    if (oldState != null && !oldState.equals(intent.getState())) {
                        intentStateChanges.put(actionCmd, intentStateChanges.getOrDefault(actionCmd, 0) + 1);
                        intentStateChangeCnt++;
                    }

                } else if (actionCmd.startsWith("withdraw-intent")) {
                    entries.add(new IntentStateTransitionEntry(WITHDRAW_INTENT_OPER, getIdx(intent.getKey()), intent.getState()));
                    oldState = globalIntentState.put(intent.getKey(), intent.getState());
                    if (oldState != null && !oldState.equals(intent.getState())) {
                        intentStateChanges.put(actionCmd, intentStateChanges.getOrDefault(actionCmd, 0) + 1);
                        intentStateChangeCnt++;
                    }

                } else if (actionCmd.startsWith("purge-intent")) {
                    entries.add(new IntentStateTransitionEntry(PURGE_INTENT_OPER, getIdx(intent.getKey()), intent.getState()));
                    if (State.REMOVED.equals(intent.getState())) {
                        globalIntentState.remove(intent.getKey());
                        appliedIntents.remove(intent.getKey());
                        intentStateChanges.put(actionCmd, intentStateChanges.getOrDefault(actionCmd, 0) + 1);
                        intentStateChangeCnt++;
                    }
                }
            }
        }
    }

    public static String getStatsHeader() {
        StringBuilder builder = new StringBuilder();
        for (byte i = 0; i < MAX_OPER; i++) {
            if (i > 0)
                builder.append(", ");
            builder.append(operToCmd[i]);
        }
        return builder.toString();
    }

    public String getStatsString() {

        StringBuilder builder = new StringBuilder();
        for (byte i = 0; i < MAX_OPER; i++) {
            if (i > 0)
                builder.append(", ");
            builder.append(numOperations[i]);
        }

        return builder.toString();
    }

    public Map<String, Integer> getIntentStateChanges() {
        return intentStateChanges;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();

        entries.forEach(k -> builder.append(k.toString()).append("\n"));

        return builder.toString();
    }

    private class IntentStateTransitionEntry {
        byte oper;      // [3-bit oper][1-bit error code]
        int idx;
        int len;
        byte[] state;
        boolean isError = false;

        public IntentStateTransitionEntry(byte oper, List<State> states) {
            this.oper = oper;
            this.idx = -1;
            this.len = states.size();
            this.state = new byte[this.len];
            for (int i = 0; i < this.len; i++) {
                state[i] = states.get(i).toByteCode();
            }
        }

        public IntentStateTransitionEntry(byte oper, byte[] byteCodes) {
            this.oper = oper;
            this.idx = -1;
            this.len = byteCodes.length;
            this.state = byteCodes;
        }

        public IntentStateTransitionEntry(byte oper, int idx, State state) {
            this.oper = oper;
            this.idx = idx;
            this.len = 1;
            this.state = new byte[1];
            this.state[0] = state.toByteCode();
        }

        public IntentStateTransitionEntry(byte oper, boolean isError) {
            this.oper = oper;
            this.isError = isError;
            this.len = 0;
            this.idx = -1;
        }

        public IntentStateTransitionEntry(byte oper, boolean isError, int idx, State state) {
            this.oper = oper;
            this.isError = isError;
            this.idx = idx;
            this.len = 1;
            this.state = new byte[1];
            this.state[0] = state.toByteCode();
        }

        public byte[] toByteArray() {
            // oper|isError|hasIdx(1B) + idx/len (4B) + payload
            int tmp = oper << 2 | (isError ? 1 : 0) | (idx < 0 ? 0 : 1);
            ByteBuffer byteBuffer;

            if (idx >= 0) {
                byteBuffer = ByteBuffer.allocate(5 + this.len)
                        .put((byte) tmp)
                        .putInt(idx)
                        .put(state);
            } else if (len > 0) {
                byteBuffer = ByteBuffer.allocate(5 + this.len)
                        .put((byte) tmp)
                        .putInt(len)
                        .put(state);
            } else {
                // len == 0 && idx < 0
                byteBuffer = ByteBuffer.allocate(1)
                        .put((byte) tmp);
            }

            return byteBuffer.array();
        }

        @Override
        public String toString() {
            StringBuilder builder = new StringBuilder();

            // 1. Is error?
            if (isError)
                builder.append("[ERR] ");

            // 2. command
            builder.append(operToCmd[oper]);

            // 3. get all states
            if (this.len > 0) {
                builder.append(": ");

                for (int i = 0; i < this.len; i++)
                    builder.append(State.shortStateFromByteCode(state[i]));
            }

            // 4. define index
            if (hasSingleMember[oper] && idx >= 0)
                builder.append(" @ ").append(idx);

            return builder.toString();
        }
    }
}
