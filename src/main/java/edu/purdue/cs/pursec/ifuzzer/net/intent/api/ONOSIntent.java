package edu.purdue.cs.pursec.ifuzzer.net.intent.api;

import com.google.gson.JsonObject;

public interface ONOSIntent extends Intent {
    public JsonObject toJson(String onosVersion);
}
