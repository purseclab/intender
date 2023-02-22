package edu.purdue.cs.pursec.ifuzzer.comm.impl;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.ONOSConstants;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterface;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse.IntentInterfaceResponseBuilder;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;

import java.net.HttpURLConnection;

public class ONOSRestInterface implements IntentInterface {

    @Override
    public IntentInterfaceResponse getIntent(String key) {

        IntentInterfaceResponseBuilder builder = new IntentInterfaceResponseBuilder();

        try {
            // Get json string
            String intentStr = ONOSUtil.getIntentFromONOS(ONOSConstants.ONOS_APP_ID, key);
            if (intentStr == null) {
                builder.errorMsg("Does not exist");
            } else {
                // Parse intent from json
                Intent intent = ONOSUtil.getIntentFromJson(intentStr);
                builder.intent(intent);
            }

        } catch (Exception e) {
            builder.errorMsg(e.getMessage());
        }

        return builder.build();
    }

    @Override
    public IntentInterfaceResponse addIntent(String intentStr) {

        String addIntentStr = intentStr;
        if (ConfigConstants.CONFIG_FUZZING_JSON_INVARIANCE || ConfigConstants.CONFIG_ENABLE_H2H_HINT_FIELD) {
            try {
                JsonObject intentJson = TestUtil.fromJson(intentStr);
                intentJson.remove("_one");
                intentJson.remove("_two");
                addIntentStr = intentJson.toString();
            } catch (JsonParseException e) {
                return new IntentInterfaceResponse(e.getMessage());
            }
        }

        IntentInterfaceResponseBuilder builder = new IntentInterfaceResponseBuilder();

        try {
            // Request intent to ONOS
            HttpURLConnection conn = ONOSUtil.setIntentToONOS(addIntentStr);
            int responseCode = conn.getResponseCode();

            builder.statusCode(responseCode);

            // If ONOS rejects intent request, send failure to scenario.
            if (responseCode >= 200 && responseCode < 300) {
                Intent onosIntent = ONOSUtil.getIntentFromJson(intentStr);
                if (onosIntent == null) {
                    builder.errorMsg("Unsupported intent");
                } else {
                    if (onosIntent.getKey() == null) {
                        String location = conn.getHeaderField("location");
                        if (location != null) {
                            String[] fields = location.split("/");
                            onosIntent.setKey(fields[fields.length - 1]);
                        }
                    }
                    builder.intent(onosIntent);
                }

            } else {
                // FIXME: send error message
                // TODO: if responseCode is 500 (Internal Server Error), restart SDN controller!

                String errorMsg = "ONOS DENY REST: " + conn.getResponseMessage();
                builder.errorMsg(errorMsg);
            }

        } catch (Exception e) {
            builder.errorMsg(e.getMessage());
        }

        return builder.build();
    }

    @Override
    public IntentInterfaceResponse modIntent(String key, String appId, String intentStr) {

        String modIntentStr;
        try {
            JsonObject intentJson = TestUtil.fromJson(intentStr);
            intentJson.addProperty("key", key);
            intentJson.addProperty("appId", appId);

            if (ConfigConstants.CONFIG_ENABLE_H2H_HINT_FIELD) {
                intentJson.remove("_one");
                intentJson.remove("_two");
            }
            modIntentStr = intentJson.toString();

        } catch (JsonParseException e) {
            return new IntentInterfaceResponse(e.getMessage());
        }

        IntentInterfaceResponseBuilder builder = new IntentInterfaceResponseBuilder();

        try {
            // Request intent to ONOS
            HttpURLConnection conn = ONOSUtil.setIntentToONOS(modIntentStr);
            int responseCode = conn.getResponseCode();
            builder.statusCode(responseCode);

            // If ONOS rejects intent request, send failure to scenario.
            if (responseCode >= 200 && responseCode < 300) {
                Intent onosIntent = ONOSUtil.getIntentFromJson(intentStr);
                if (onosIntent == null) {
                    builder.errorMsg("Unsupported intent");
                } else {
                    builder.intent(onosIntent);
                }

            } else {
                // FIXME: send error message
                // TODO: if responseCode is 500 (Internal Server Error), restart SDN controller!

                String errorMsg = "ONOS DENY REST: " + conn.getResponseMessage();
                builder.errorMsg(errorMsg);
            }

        } catch (Exception e) {
            builder.errorMsg(e.getMessage());
        }

        return builder.build();
    }

    @Override
    public IntentInterfaceResponse deleteIntent(String key) {
        IntentInterfaceResponseBuilder builder = new IntentInterfaceResponseBuilder();

        try {
            // Request deletion to ONOS
            HttpURLConnection conn = ONOSUtil.delIntentToONOS(ONOSConstants.ONOS_APP_ID, key);
            int responseCode = conn.getResponseCode();
            builder.statusCode(responseCode);

            // If ONOS rejects intent request, send failure to scenario.
            if (responseCode < 200 || responseCode >= 300) {
                // FIXME: send error message
                // TODO: if responseCode is 500 (Internal Server Error), restart SDN controller!

                String errorMsg = "ONOS DENY REST: " + conn.getResponseMessage();
                builder.errorMsg(errorMsg);
            }

        } catch (Exception e) {
            builder.errorMsg(e.getMessage());
        }

        return builder.build();
    }

    @Override
    public IntentInterfaceResponse withdrawIntent(String key, String appId) {
        return new IntentInterfaceResponse("unsupported");
    }

    @Override
    public IntentInterfaceResponse purgeIntent(String key, String appId) {
        return new IntentInterfaceResponse("unsupported");
    }
}
