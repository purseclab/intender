package edu.purdue.cs.pursec.ifuzzer.comm.impl;

import com.google.gson.*;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.ONOSConstants;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterface;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse.IntentInterfaceResponseBuilder;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

public class ONOSAgentInterface implements IntentInterface {

    private final ONOSAgentServer server;

    public ONOSAgentInterface() {
        server = new ONOSAgentServer();
        server.start();
    }

    @Override
    public IntentInterfaceResponse getIntent(String key) {
        // TODO: implement get intent via agent
        ONOSRestInterface restInterface = new ONOSRestInterface();
        return restInterface.getIntent(key);
    }

    @Override
    public IntentInterfaceResponse addIntent(String intentStr) {
        // NOTE: do not send wrong format of json
        String addIntentStr;
        try {
            JsonObject intentJson = TestUtil.fromJson(intentStr);
            if (ConfigConstants.CONFIG_ENABLE_H2H_HINT_FIELD) {
                intentJson.remove("_one");
                intentJson.remove("_two");
            }
            addIntentStr = intentJson.toString();
        } catch (JsonParseException e) {
            return new IntentInterfaceResponse(e.getMessage());
        }

        return server.addIntent(addIntentStr);
    }

    @Override
    public IntentInterfaceResponse deleteIntent(String key) {
        IntentInterfaceResponse response = withdrawIntent(key, ONOSConstants.ONOS_APP_ID);
        if (!response.isSuccess())
            return response;

        return purgeIntent(key, ONOSConstants.ONOS_APP_ID);
    }

    @Override
    public IntentInterfaceResponse modIntent(String key, String appId, String intentStr) {
        // NOTE: do not send wrong format of json
        String modIntentStr;
        try {
            JsonObject intentJson = TestUtil.fromJson(intentStr);
            // Is it needed..?
            intentJson.addProperty("key", key);
            if (ConfigConstants.CONFIG_ENABLE_H2H_HINT_FIELD) {
                intentJson.remove("_one");
                intentJson.remove("_two");
            }
            modIntentStr = intentJson.toString();
        } catch (JsonParseException e) {
            return new IntentInterfaceResponse(e.getMessage());
        }

        return server.modIntent(key, appId, modIntentStr);
    }

    @Override
    public IntentInterfaceResponse withdrawIntent(String key, String appId) {
        /* TODO */
        return server.withdrawIntent(key, appId);
    }

    @Override
    public IntentInterfaceResponse purgeIntent(String key, String appId) {
        /* TODO */
        return server.purgeIntent(key, appId);
    }

    private class ONOSAgentServer extends Thread {
        ONOSAgentHandler currentHandler;

        private boolean isONOSAgentAlive() {
            // Wait 3 seconds
            for (int i = 0; i < 6 && currentHandler == null; i++) {
                try {
                    TimeUnit.MILLISECONDS.sleep(500);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                    break;
                }
            }

            return (currentHandler != null);
        }

        public IntentInterfaceResponse getIntent(String key) {
            if (!isONOSAgentAlive())
                return new IntentInterfaceResponse("Check whether ONOS agent is running!");

            return currentHandler.getIntent(key);
        }

        public IntentInterfaceResponse addIntent(String intentStr) {
            if (!isONOSAgentAlive())
                return new IntentInterfaceResponse("Check whether ONOS agent is running!");

            return currentHandler.addIntent(intentStr);
        }

        public IntentInterfaceResponse modIntent(String key, String appId, String intentStr) {
            if (!isONOSAgentAlive())
                return new IntentInterfaceResponse("Check whether ONOS agent is running!");

            return currentHandler.modIntent(key, appId, intentStr);
        }

        public IntentInterfaceResponse withdrawIntent(String key, String appId) {
            if (!isONOSAgentAlive())
                return new IntentInterfaceResponse("Check whether ONOS agent is running!");

            return currentHandler.withdrawIntent(key, appId);
        }

        public IntentInterfaceResponse purgeIntent(String key, String appId) {
            if (!isONOSAgentAlive())
                return new IntentInterfaceResponse("Check whether ONOS agent is running!");

            return currentHandler.purgeIntent(key, appId);
        }

        @Override
        public void run() {
            try {
                ServerSocket serverSocket = new ServerSocket(9000);

                // Allow only one connection
                Socket socket = serverSocket.accept();

                currentHandler = new ONOSAgentHandler(socket);

                // TODO: support restarting ONOS controller

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    class ONOSAgentHandler {
        private final Socket socket;
        private final BufferedReader in;
        private final PrintWriter out;

        public ONOSAgentHandler(Socket socket) throws IOException {
            this.socket = socket;
            // Get input and output streams
            this.in = new BufferedReader( new InputStreamReader(socket.getInputStream()));
            this.out = new PrintWriter(socket.getOutputStream());
        }

        public IntentInterfaceResponse getIntent(String key) {
            /*
             * < REQ >
             * GET
             * key:[key]
             */
            out.println("GET");
            // TODO: input appId
            out.println("key:" + key);
            out.flush();

            /*
             * < RESP >
             * length:[length]
             * [intentStr]
             */
            IntentInterfaceResponseBuilder builder = new IntentInterfaceResponseBuilder();
            try {
                String line = in.readLine().trim();
                if (line.startsWith("length:")) {
                    // Get length
                    int len = Integer.parseInt(line.substring("length:".length()));
                    char [] data = new char[len + 1];

                    // Read intentStr
                    int readLen = in.read(data, 0, len);
                    data[readLen] = 0;
                    String intentStr = new String(data);

                    // Parse intentStr
                    Intent onosIntent = ONOSUtil.getIntentFromJson(intentStr);
                    if (onosIntent == null) {
                        builder.errorMsg("Unsupported intent");
                    } else {
                        builder.intent(onosIntent);
                    }

                } else if (line.startsWith("error:")) {
                    builder.errorMsg(line.substring("error:".length()));
                } else {
                    builder.errorMsg("wrong message");
                }
            } catch (Exception e) {
                builder.errorMsg(e.getMessage());
            }

            return builder.build();
        }

        public IntentInterfaceResponse addIntent(String intentStr) {
            /*
             * < REQ >
             * ADD
             * length:[length]
             * [intentStr]
             */
            out.println("ADD");
            out.println(String.format("length:%d", intentStr.length()));
            out.print(intentStr);
            out.flush();

            /*
             * < RESP >
             * key:[key]
             */
            IntentInterfaceResponseBuilder builder = new IntentInterfaceResponseBuilder();
            try {
                String line = in.readLine().trim();

                if (line.startsWith("key:")) {
                    Intent onosIntent = ONOSUtil.getIntentFromJson(intentStr);
                    if (onosIntent == null) {
                        builder.errorMsg("Unsupported intent");
                    } else {
                        if (onosIntent.getKey() == null)
                            onosIntent.setKey(line.substring("key:".length()));
                        builder.intent(onosIntent);
                    }

                } else if (line.startsWith("error:")) {
                    builder.errorMsg(line.substring("error:".length()));
                } else {
                    builder.errorMsg("wrong message");
                }
            } catch (Exception e) {
                builder.errorMsg(e.getMessage());
            }

            return builder.build();
        }

        public IntentInterfaceResponse modIntent(String key, String appId, String intentStr) {
            /*
             * < REQ >
             * MODIFY
             * appId:[appId]
             * key:[key]
             * length:[length]
             * [intentStr]
             */
            out.println("MODIFY");
            out.println("appId:" + appId);
            out.println("key:" + key);
            out.println(String.format("length:%d", intentStr.length()));
            out.print(intentStr);
            out.flush();

            /*
             * < RESP >
             * key:[key]
             */
            IntentInterfaceResponseBuilder builder = new IntentInterfaceResponseBuilder();
            try {
                String line = in.readLine().trim();

                if (line.startsWith("key:")) {
                    Intent onosIntent = ONOSUtil.getIntentFromJson(intentStr);
                    if (onosIntent == null) {
                        builder.errorMsg("Unsupported intent");
                    } else {
                        builder.intent(onosIntent);
                    }

                } else if (line.startsWith("error:")) {
                    builder.errorMsg(line.substring("error:".length()));
                } else {
                    builder.errorMsg("wrong message");
                }
            } catch (Exception e) {
                builder.errorMsg(e.getMessage());
            }

            return builder.build();
        }

        public IntentInterfaceResponse withdrawIntent(String key, String appId) {
            /*
             * < REQ >
             * WITHDRAW
             * appId:[appId]
             * key:[key]
             */
            out.println("WITHDRAW");
            out.println("appId:" + appId);
            out.println("key:" + key);
            out.flush();

            /*
             * < RESP >
             * key:[key]
             */
            try {
                String line = in.readLine().trim();

                if (line.startsWith("key:")) {
                    return new IntentInterfaceResponse();

                } else if (line.startsWith("error:")) {
                    return new IntentInterfaceResponse(line.substring("error:".length()));
                } else {
                    return new IntentInterfaceResponse("wrong message");
                }
            } catch (Exception e) {
                return new IntentInterfaceResponse(e.getMessage());
            }
        }

        public IntentInterfaceResponse purgeIntent(String key, String appId) {
            /*
             * < REQ >
             * PURGE
             * appId:[appId]
             * key:[key]
             */
            out.println("PURGE");
            out.println("appId:" + appId);
            out.println("key:" + key);
            out.flush();

            /*
             * < RESP >
             * key:[key]
             */
            try {
                String line = in.readLine().trim();

                if (line.startsWith("key:")) {
                    return new IntentInterfaceResponse();

                } else if (line.startsWith("error:")) {
                    return new IntentInterfaceResponse(line.substring("error:".length()));
                } else {
                    return new IntentInterfaceResponse("wrong message");
                }
            } catch (Exception e) {
                return new IntentInterfaceResponse(e.getMessage());
            }
        }
    }
}
