package edu.purdue.cs.pursec.ifuzzer.api;

// TODO: define these values in config.properties
// TODO: make afl_postprocessor to enforce json format
public class ConfigConstants {
    // TODO: refer scenario guidance from scenario json file
    public static final String CONFIG_FUZZING_SCENARIO_GUIDANCE = "SingleIntentGuidance";
    public static final String CONFIG_FUZZING_INTENT_GUIDANCE = "NoIntentGuidance";
    public static final String CONFIG_FUZZING_PACKET_GUIDANCE = "NoPacketGuidance";
    public static final boolean CONFIG_ACCEPT_INSTALLING_AS_ERROR = true;
    public static final boolean STOPFUZZ_BUG4 = true;
    public static final int CONFIG_INTENT_CHECK_INTERVAL_MS = 50;
    public static final int CONFIG_INTENT_WAIT_TIMEOUT = 9;
    public static final int CONFIG_TOPOLOGY_CHECK_INTERVAL_MS = 1000;
    public static final int CONFIG_TOPOLOGY_WAIT_TIMEOUT = 0;
    public static final int CONFIG_TOPOLOGY_HOST_WAIT_TIMEOUT = 10;
    public static final int CONFIG_MEASURE_STAT_INTERVAL = 5;

    /*
     * CONFIG_FUZZING_MAX_INSTALLED_INTENT:
     *   - 0: no limit in number of installed (TODO: support dp-test for multiple intents)
     *   - 1: allow only single installed intent at a time
     *   - > 2: allow two or more installed intent at a time
     */
    public static final boolean CONFIG_SET_INVALID_AS_SEMANTIC = true;
    public static final boolean CONFIG_ENABLE_STATIC_MIRROR = true;
    public static final int CONFIG_FUZZING_MAX_INSTALLED_INTENT = 0;
    public static final boolean CONFIG_FUZZING_JSON_INVARIANCE = false;
    public static final boolean CONFIG_FUZZING_TYPE_INVARIANCE = false;
    public static final boolean CONFIG_ENABLE_COVERAGE_LOGGING = true;
    public static final boolean CONFIG_RUN_FUZZING_IN_LOCAL = true;
    public static final boolean CONFIG_ENABLE_H2H_HINT_FIELD = false;
    public static final int COVERAGE_MAP_SIZE = 1 << 16;
    public static final boolean CONFIG_ENABLE_SELECTOR = false;
    public static final boolean CONFIG_ENABLE_MUTATE_TOPOLOGY = true;
    public static final boolean CONFIG_FUZZING_HOST_IN_SUBNET = true;
    public static final boolean CONFIG_ENABLE_CODE_COVERAGE_FILTER = true;
    public static final boolean CONFIG_DISABLE_SAME_POINTS_OF_P2P_INTENT = true;
    public static final boolean CONFIG_DP_VERIFY_WITH_DELETION = true;
    public static final boolean CONFIG_TRUNCATE_ACTIONS_AFTER_ERROR = true;
    public static boolean CONFIG_ENABLE_TEST_EACH_ERROR_INTENT = true;
    public static final boolean CONFIG_REPLAY_CODE_COVERAGE_INCLUSIVE = false;
    public static final int CONFIG_NUM_CODE_SEMANTIC_LEVELS = 8;
    public static final int CONFIG_PACKET_FUZZING_TIMEOUT = 0;                  /* used by PazzPacketGuidance */
    public static final int CONFIG_PAZZ_PACKET_HEADER_LEN = 32;                 /* used by FlowRuleStore */
    public static final String CONFIG_PAZZ_CONSISTENCY_TESTER_IP = "";
}
