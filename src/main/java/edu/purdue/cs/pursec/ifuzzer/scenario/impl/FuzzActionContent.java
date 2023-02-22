package edu.purdue.cs.pursec.ifuzzer.scenario.impl;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;

import java.io.IOException;
import java.util.UUID;

public class FuzzActionContent {
    // Content is JSON format
    // TODO: change content to (id, cmd)
    JsonObject content;

    public FuzzActionContent(JsonObject content) {
        this.content = content;
    }

    public static FuzzActionContent of(JsonObject content) throws JsonParseException {
        if (content.has("intent") || content.has("intentFilePath") ||
                content.has("intentRandFilePath"))
            return new FuzzActionIntentContent(content);
        else
            return new FuzzActionContent(content);
    }

    public FuzzActionContent deepCopy() {
        return new FuzzActionContent(this.content.deepCopy());
    }

    public JsonObject getContent() {
        return content;
    }

    public String setNewId() {
        String newId = UUID.randomUUID().toString();
        this.setId(newId);
        return newId;
    }

    public void setId(String id) {
        content.addProperty("id", id);
    }

    public void setIntentId(String id) {
        content.addProperty("intentId", id);
    }

    public String getId() {
        if (content.has("id"))
            return content.get("id").getAsString();
        else if (content.has("intentId"))
            return content.get("intentId").getAsString();
        else
            return null;
    }

    public JsonObject toJsonObject() throws IOException {
        return content;
    }

    @Override
    public String toString() {
        return content.toString();
    }

    @Override
    public boolean equals(Object o) {
        return (o instanceof FuzzActionContent && ((FuzzActionContent)o).getContent().equals(this.getContent()));
    }
}
