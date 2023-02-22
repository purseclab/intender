package edu.purdue.cs.pursec.ifuzzer.net.intent.api;


public class IntentEvent {
    public enum Type {
        INIT,           // Initialized

        CHECK_REQ,      // Req by FuzzSvc
        CHECK_FAILED,   // Failed by DecisionSvc    -> Error 1
        CHECKED,        // Checked by DecisionSvc

        RUN_TEST,       // Req by TestMgr (PAZZ)
        TEST_REQ,       // Req by TestMgr
        TEST_FAILED,    // Failed by TestMgr        -> Error 2
        STOP_TEST,      // Req by Test-Agent
        DONE            // Success
    }

    private final String key;
    private final String actionId;
    private final Intent intent;
    private final Type type;
    private final int seq;
    private String errorMsg;

    public IntentEvent(String key, int seq, Intent intent, String actionId, Type type) {
        this.key = key;
        this.seq = seq;
        this.intent = intent;
        this.type = type;
        this.actionId = actionId;
    }

    public IntentEvent(String key, int seq, Intent intent, String actionId, Type type, String errorMsg) {
        this.key = key;
        this.seq = seq;
        this.intent = intent;
        this.type = type;
        this.actionId = actionId;
        this.errorMsg = errorMsg;
    }

    public String getKey() {
        return key;
    }

    public int getSeq() {
        return seq;
    }

    public String getActionId() {
        return actionId;
    }

    public Intent getIntent() {
        return intent;
    }

    public Type getType() {
        return type;
    }

    public String getErrorMsg() {
        return errorMsg;
    }
}
