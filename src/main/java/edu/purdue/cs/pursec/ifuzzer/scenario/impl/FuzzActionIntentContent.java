package edu.purdue.cs.pursec.ifuzzer.scenario.impl;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.ZestIntentGuidance.Input;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.ZestIntentGuidance.SeedInput;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;

public class FuzzActionIntentContent extends FuzzActionContent {
    static final String intentPath = IFuzzer.intentPath;
    String intentJsonStr;
    private Input intentInput;

    public FuzzActionIntentContent(JsonObject content) throws JsonParseException {
        super(content);

        // Get intent
        if (content.has("intent")) {
            this.intentJsonStr = content.get("intent").toString();

            if (ConfigConstants.CONFIG_FUZZING_INTENT_GUIDANCE.equals("ZestIntentGuidance")) {
                try {
                    this.intentInput = FuzzUtil.getZestInputFromIntentJson(this.intentJsonStr);
                } catch (IOException e) {
                    this.intentInput = null;
                    throw new JsonParseException(e);
                }
            }

        } else if (content.has("intentFilePath")) {
            // Read file
            String intentFilePath = content.get("intentFilePath").getAsString();
            try {
                this.intentJsonStr = new String(Files.readAllBytes(Paths.get(intentFilePath)));
            } catch (IOException e) {
                throw new JsonParseException("error while reading intentFilePath: " + e.getMessage());
            }
        } else if (content.has("intentRandFilePath")) {
            // Read file
            String intentFilePath = content.get("intentRandFilePath").getAsString();
            try {
                this.intentInput = new SeedInput(new File(intentFilePath));
                this.intentJsonStr = FuzzUtil.getIntentJsonFromGenerator(intentInput).toString();
            } catch (IOException e) {
                throw new JsonParseException("error while reading intentRandFilePath: " + e.getMessage());
            }

        } else {
            throw new JsonParseException("No intent or intentFilePath field");
        }
    }

    public FuzzActionIntentContent(JsonObject content, String intentJsonStr) {
        super(content);
        this.intentJsonStr = intentJsonStr;
    }

    public FuzzActionIntentContent(JsonObject content, String intentJsonStr, Input intentInput) {
        super(content);
        this.intentJsonStr = intentJsonStr;
        this.intentInput = intentInput;
    }

    public String getIntent() {
        return intentJsonStr;
    }

    public void setIntent(String intentJsonStr) {
        this.intentJsonStr = intentJsonStr;
    }

    public Input getIntentInput() {
        return intentInput;
    }

    public void setIntentInput(Input intentInput) throws IOException {
        this.intentInput = intentInput;
        this.intentJsonStr = FuzzUtil.getIntentJsonFromGenerator(this.intentInput).toString();
    }

    @Override
    public FuzzActionIntentContent deepCopy() {
        return new FuzzActionIntentContent(this.content.deepCopy(), this.intentJsonStr, this.intentInput);
    }

    @Override
    public String toString() {
        return super.toString() + ", " + intentJsonStr;
    }

    private JsonObject toJsonObjectWithFile(JsonObject jsonObject, String intentJsonStr) throws IOException {
        // store intent as a file
        String fileName = LocalDateTime.now()
                .format((DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS"))) + ".txt";
        String intentFilePath = intentPath + File.separator + fileName;
        FileUtils.writeStringToFile(new File(intentFilePath), intentJsonStr, StandardCharsets.US_ASCII);

        jsonObject.remove("intent");
        jsonObject.addProperty("intentFilePath", intentFilePath);

        return jsonObject;
    }

    @Override
    public JsonObject toJsonObject() throws IOException {
        JsonObject jsonObject = super.toJsonObject();

        try {
            if (intentJsonStr == null) {
                toJsonObjectWithFile(jsonObject, null);

            } else {
                JsonElement intentJsonElem = JsonParser.parseReader(new StringReader(intentJsonStr));

                // store intent inside of JsonObject
                jsonObject.remove("intentFilePath");
                jsonObject.add("intent", intentJsonElem);
            }

        } catch (JsonParseException e) {
            toJsonObjectWithFile(jsonObject, intentJsonStr);
        }

        return jsonObject;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof FuzzActionIntentContent))
            return false;

        FuzzActionIntentContent content = (FuzzActionIntentContent)o;
        if (!content.getContent().equals(this.getContent()))
            return false;

        if (!content.getIntent().equals(this.getIntent()))
            return false;

        return true;
    }
}
