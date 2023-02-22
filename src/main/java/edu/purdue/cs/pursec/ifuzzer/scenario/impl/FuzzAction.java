package edu.purdue.cs.pursec.ifuzzer.scenario.impl;

import com.google.gson.*;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.GuidanceException;
import edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

public class FuzzAction {
    private static Logger log = LoggerFactory.getLogger(FuzzAction.class);
    String id;
    String state = "REQ";       // REQ, DONE
    String subState = "";       // ACCEPTED, INSTALLED, VERIFIED
    String actionCmd = null;
    FuzzActionContent content = null;
    FuzzActionContent seedContent = null;
    boolean isInitAction = false;
    boolean sync;
    String errorMsg = null;
    boolean doesRequireLogging = false;
    private boolean stopFuzz = false;
    Exception exception = null;
    Object retObject;
    boolean isSingleIntentDpError = false;
    private IntentInterfaceResponse response = null;
    private long durationMillis;
    private int waitCnt = 1;
    boolean isFail = false;

    public static FuzzAction loadHostAction;

    static {
        loadHostAction = new FuzzAction();
        loadHostAction.id = "load-hosts";
        loadHostAction.actionCmd = "load-hosts";
        loadHostAction.content = new FuzzActionContent(new JsonObject());
    }

    private FuzzAction() {}

    // Constructor for copy
    private FuzzAction(FuzzAction action) {
        this.id = action.getId();
        this.actionCmd = action.getActionCmd();
        if (action.getContent() != null)
            this.content = action.getContent().deepCopy();
        this.seedContent = action.seedContent;
        this.sync = action.isSync();
        this.isInitAction = action.isInitAction();
    }

    public FuzzAction(String id) {
        this.id = id;
    }

    public FuzzAction(String id, JsonObject jsonObject) throws JsonParseException {
        // TODO: builder for FuzzAction

        this.id = id;

        if (jsonObject.has("action"))
            this.actionCmd = jsonObject.get("action").getAsString();

        if (jsonObject.has("content")) {
            JsonObject contentJson = jsonObject.get("content").getAsJsonObject();
            this.content = FuzzActionContent.of(contentJson);
            this.seedContent = content.deepCopy();
        }

        if (jsonObject.has("exec-mode")) {
            String execMode = jsonObject.get("exec-mode").getAsString();
            if (execMode.toLowerCase().startsWith("async")) {
                this.sync = false;
            } else if (execMode.toLowerCase().startsWith("sync")) {
                this.sync = true;
            }
        } else {
            this.sync = isSyncCommand();
        }
    }

    public static FuzzAction copy(FuzzAction action) {
        return new FuzzAction(action);
    }

    public static FuzzAction deepcopy(FuzzAction action) {
        FuzzAction newAction = new FuzzAction(action);
        newAction.setRetObject(action.getRetObject());
        newAction.state = action.state;
        newAction.errorMsg = action.errorMsg;
        newAction.isSingleIntentDpError = action.isSingleIntentDpError;
        return newAction;
    }

    public static FuzzAction change(String actionCmd, FuzzAction action) {
        // copy first
        FuzzAction newAction = FuzzAction.copy(action);
        newAction.actionCmd = actionCmd;
        return newAction;
    }

    public static FuzzAction fuzz(FuzzAction action)
            throws IOException, JsonSyntaxException, EndFuzzException, GuidanceException {

        return ScenarioStore.scenarioGuidance.getRandomAction(action);
    }

    public static FuzzAction cpVerifyAction(String intentKey) {
        FuzzAction fuzzAction = new FuzzAction();
        fuzzAction.id = "cp-verify-intent-" + intentKey;
        fuzzAction.actionCmd = "cp-verify-intent";
        fuzzAction.content = new FuzzActionContent(new JsonObject());
        fuzzAction.content.setIntentId(intentKey);
        fuzzAction.setSync();

        return fuzzAction;
    }

    public static FuzzAction dpVerifyAction(String intentKey) {
        FuzzAction fuzzAction = new FuzzAction();
        fuzzAction.id = "dp-verify-intent-" + intentKey;
        fuzzAction.actionCmd = "dp-verify-intent";
        fuzzAction.content = new FuzzActionContent(new JsonObject());
        fuzzAction.content.setIntentId(intentKey);
        fuzzAction.setSync();

        return fuzzAction;
    }

    public static FuzzAction delIntentAction(String intentKey) {
        FuzzAction fuzzAction = new FuzzAction();
        fuzzAction.id = "del-intent-" + intentKey;
        fuzzAction.actionCmd = "del-intent";
        fuzzAction.content = new FuzzActionContent(ONOSUtil.createNewContentJson());
        fuzzAction.content.setId(intentKey);
        fuzzAction.setSync();

        return fuzzAction;
    }

    public boolean isTopoOperation() {
        String[] actionCmd = this.actionCmd.split("-");
        if (actionCmd.length != 2)
            return false;

        String elemType = actionCmd[1];
        return elemType.equals("link") || elemType.equals("device") || elemType.equals("host");
    }

    public FuzzActionContent getSeedContent() {
        return seedContent;
    }

    public boolean isInitAction() {
        return isInitAction;
    }

    public void setInitAction() {
        isInitAction = true;
    }

    public void setSync() {
        this.sync = true;
    }

    public boolean isSync() {
        return this.sync;
    }

    public void setRandomId() {
        this.id = UUID.randomUUID().toString();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setNewIntentId() {
        this.content.setNewId();
    }

    public void setActionCmd(String actionCmd) {
        this.actionCmd = actionCmd;
    }

    public String getActionCmd() {
        return actionCmd;
    }

    public FuzzActionContent getContent() {
        return content;
    }

    public void setContent(FuzzActionContent content) {
        this.content = content;
    }

    public boolean isProcessing() {
        if (this.waitCnt > 0)
            return true;
        return (this.state.equals("REQ"));
    }

    public void success() {
        if (this.isFail)
            this.state = "ERROR";
        else
            this.state = "SUCCESS";
    }

    public boolean isSuccess() {
        return (this.state.equals("SUCCESS"));
    }

    public void error(String errorMsg) {
        this.state = "ERROR";
        this.errorMsg = errorMsg;
    }

    public Object getRetObject() {
        return retObject;
    }

    public void setRetObject(Object retObject) {
        this.retObject = retObject;
    }

    public IntentInterfaceResponse getResponse() {
        return response;
    }

    public void setResponse(IntentInterfaceResponse response) {
        this.response = response;
        if (this.response.getErrorMsg() != null)
            this.error(this.response.getErrorMsg());
    }

    public boolean doesRequireLogging() {
        return this.doesRequireLogging;
    }

    public void setReplayLogging(boolean doesRequireLogging) {
        this.doesRequireLogging = doesRequireLogging;
    }

    public void setStopFuzz(boolean stopFuzz) {
        this.stopFuzz = stopFuzz;
    }

    public boolean stopFuzz() {
        return this.stopFuzz;
    }

    public void setSubState(String subState) {
        if (this.subState.length() > 0)
            this.subState += ",";
        this.subState += subState;
    }

    public void setException(Exception exception) {
        this.exception = exception;
    }

    public String getErrorMsg() {
        return this.errorMsg;
    }

    public boolean isError() {
        return (this.state.equals("ERROR"));
    }

    public boolean isAccepted() {
        return (this.subState.contains("ACCEPTED"));
    }

    public boolean isInstalled() {
        return (this.subState.contains("INSTALLED"));
    }

    public boolean isVerified() {
        return (this.subState.contains("VERIFIED"));
    }

    public boolean hasSyntaxError() {
        return (this.exception instanceof JsonSyntaxException);
    }

    public boolean isSingleIntentDpError() {
        return isSingleIntentDpError;
    }

    public void setSingleIntentDpError(boolean singleIntentDpError) {
        isSingleIntentDpError = singleIntentDpError;
    }

    public long getDurationMillis() {
        return durationMillis;
    }

    public void setDurationMillis(Instant start, Instant end) {
        this.durationMillis = Duration.between(start, end).toMillis();
    }

    public int decWaitCnt() {
        return --waitCnt;
    }

    public int decWaitCnt(boolean isFail) {
        if (isFail)
            this.isFail = true;
        return decWaitCnt();
    }

    public void setWaitCnt(int waitCnt) {
        this.waitCnt = waitCnt;
    }

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

    private boolean isSyncCommand() {
        if (this.actionCmd == null)
            return false;

        String cmd = this.actionCmd.toLowerCase();
        if (cmd.endsWith("verify-intent") || cmd.endsWith("-topo") || cmd.equals("del-intent")) {
            return true;
        } else if (isTopoOperation()) {
            return true;
        }

        return false;
    }

    public JsonObject toJsonObject() throws IOException {
        JsonObject jsonObject = new JsonObject();

        if (this.actionCmd != null)
            jsonObject.addProperty("action", this.actionCmd);

        if (this.content != null)
            jsonObject.add("content", this.content.toJsonObject());

        jsonObject.addProperty("exec-mode", this.sync ? "sync" : "async");
        jsonObject.addProperty("init", this.isInitAction);

        return jsonObject;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof FuzzAction))
            return false;

        FuzzAction action = (FuzzAction)o;

        if (this.actionCmd == null) {
            if (action.getActionCmd() != null)
                return false;
        } else if (!this.actionCmd.equals(action.getActionCmd())) {
            return false;
        }

        if (!this.content.equals(action.getContent()))
            return false;

        if (this.sync != action.isSync())
            return false;

        return true;
    }
}
