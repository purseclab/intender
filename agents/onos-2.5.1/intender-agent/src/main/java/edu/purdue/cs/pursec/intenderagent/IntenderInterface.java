package edu.purdue.cs.pursec.intenderagent;

import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.purdue.cs.pursec.intenderagent.codec.IntenderCodec;
import org.onosproject.codec.JsonCodec;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flowobjective.FlowObjectiveService;
import org.onosproject.net.host.HostService;
import org.onosproject.net.intent.*;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.topology.TopologyService;
import org.slf4j.Logger;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.Socket;
import java.util.concurrent.TimeUnit;

import static org.onlab.util.Tools.nullIsNotFound;
import static org.slf4j.LoggerFactory.getLogger;

public class IntenderInterface extends Thread {
    private final Logger log = getLogger(getClass());
    private final IntenderAgent app;
    private final IntenderCodec context;
    private BufferedReader in;
    private PrintStream out;

    public IntenderInterface(IntenderAgent app) {
        this.app = app;
        this.context = new IntenderCodec(app.codecService);
        context.registerService(IntentService.class, app.intentService);
        context.registerService(CoreService.class, app.coreService);
        context.registerService(FlowObjectiveService.class, app.flowObjectiveService);
        context.registerService(FlowRuleService.class, app.flowRuleService);
        context.registerService(HostService.class, app.hostService);
        context.registerService(PacketService.class, app.packetService);
        context.registerService(TopologyService.class, app.topologyService);
    }

    /*
     * TODO: Try to reconnect when the connection is closed
     */
    @Override
    public void run() {
        while (true) {
            try {

                Socket socket;
                while (true) {
                    try {
                        socket = new Socket("127.0.0.1", 9000);
                        break;
                    } catch (ConnectException e) {
                        TimeUnit.MILLISECONDS.sleep(500);
                    }
                }

                log.info("Connect to server");

                out = new PrintStream(socket.getOutputStream());
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

            } catch (Exception e) {
                log.error("Fail to connect server: " + e.getMessage());
            }

            while (true) {
                try {
                    String command = in.readLine();
                    if (command == null)
                        break;
                    else
                        command = command.trim();

                    if (command.equals("ADD")) {
                        String line = in.readLine().trim();
                        if (line.startsWith("length:")) {
                            // Get length
                            int len = Integer.parseInt(line.substring("length:".length()));
                            char[] data = new char[len + 1];

                            // Read intentStr
                            log.info("Read {} length", len);
                            int readLen = in.read(data, 0, len);
                            data[readLen] = 0;
                            String dataStr = new String(data);

                            try {
                                log.info("Parse data: {} ({} length)", dataStr, readLen);
                                ObjectNode root = (ObjectNode) context.mapper().readTree(dataStr);

                                log.info("Decode Json into intent: {}", root.toString());
                                Intent intent = context.codec(Intent.class).decode(root, context);

                                log.info("Submit intent to service");
                                app.intentService.submit(intent);

                                log.info("Send intent key: {}", intent.key().toString());
                                out.println("key:" + intent.key());
                            } catch (Exception e) {
                                out.println("error:unsupported intent: " + e.getMessage());
                            }

                        } else {
                            out.println("error:wrong message");
                        }

                    } else if (command.equals("MODIFY")) {
                        String line = in.readLine().trim();

                        // Get AppId
                        if (!line.startsWith("appId:")) {
                            out.println(String.format("error:Wrong request message %s", line));
                            out.flush();
                            continue;
                        }
                        String appIdStr = line.substring("appId:".length());
                        final ApplicationId appId = app.coreService.getAppId(appIdStr);
                        if (appId == null) {
                            out.println(String.format("error:Wrong appId %s", appIdStr));
                            out.flush();
                            continue;
                        }

                        // Get Key
                        line = in.readLine().trim();
                        if (!line.startsWith("key:")) {
                            out.println(String.format("error:Wrong request message %s", line));
                            out.flush();
                            continue;
                        }
                        String keyStr = line.substring("key:".length());

                        // Get final key from keyStr and appId
                        Key key = Key.of(Long.decode(keyStr), appId);
                        log.info("{} intent appId:{}, key:{}", command, appIdStr, keyStr);

                        line = in.readLine().trim();
                        if (line.startsWith("length:")) {
                            // Get length
                            int len = Integer.parseInt(line.substring("length:".length()));
                            char[] data = new char[len + 1];

                            // Read intentStr
                            log.info("Read {} length", len);
                            int readLen = in.read(data, 0, len);
                            data[readLen] = 0;
                            String dataStr = new String(data);

                            // Get to-be-modified intent (is it needed?)
//                            Intent intent = app.intentService.getIntent(key);
//                            if (intent == null) {
//                                log.error("intent is not found: {}", key);
//                                out.println("error:Not found");
//                                out.flush();
//                                continue;
//                            }

                            try {
                                log.info("Parse data: {} ({} length)", dataStr, readLen);
                                ObjectNode root = (ObjectNode) context.mapper().readTree(dataStr);

                                log.info("Decode Json into intent: {}", root.toString());
                                Intent intent = context.codec(Intent.class).decode(root, context);

                                log.info("Submit intent to service");
                                app.intentService.submit(intent);
                                if (!intent.key().equals(key)) {
                                    log.error("key is different - req:{} vs stored:{}", key, intent.key());
                                    out.println("error:Not found");
                                } else {
                                    log.info("Send intent key: {}", intent.key().toString());
                                    out.println("key:" + intent.key());
                                }
                            } catch (Exception e) {
                                out.println("error:unsupported intent: " + e.getMessage());
                            }

                        } else {
                            out.println("error:wrong message");
                        }

                    } else if (command.equals("WITHDRAW") || command.equals("PURGE") || command.equals("GET")) {
                        String line = in.readLine().trim();

                        // Get AppId
                        if (!line.startsWith("appId:")) {
                            out.println(String.format("error:Wrong request message %s", line));
                            out.flush();
                            continue;
                        }
                        String appIdStr = line.substring("appId:".length());
                        final ApplicationId appId = app.coreService.getAppId(appIdStr);
                        if (appId == null) {
                            out.println(String.format("error:Wrong appId %s", appIdStr));
                            out.flush();
                            continue;
                        }

                        // Get Key
                        line = in.readLine().trim();
                        if (!line.startsWith("key:")) {
                            out.println(String.format("error:Wrong request message %s", line));
                            out.flush();
                            continue;
                        }
                        String keyStr = line.substring("key:".length());

                        // Get final key from keyStr and appId
                        Key key = Key.of(Long.decode(keyStr), appId);
                        log.info("{} intent appId:{}, key:{}", command, appIdStr, keyStr);

                        // Get intent
                        Intent intent = app.intentService.getIntent(key);
                        if (intent == null) {
                            log.error("intent is not found: {}", key);
                            out.println("error:Not found");

                        } else if (command.equals("WITHDRAW")) {
                            log.info("Withdraw intent");
                            app.intentService.withdraw(intent);
                            out.println("key:" + intent.id());

                        } else if (command.equals("PURGE")) {
                            log.info("Purge intent");
                            app.intentService.purge(intent);
                            out.println("key:" + intent.id());

                        } else if (command.equals("GET")) {
                            final ObjectNode root;
                            if (intent instanceof HostToHostIntent) {
                                root = context.codec(HostToHostIntent.class).encode((HostToHostIntent) intent, context);
                            } else if (intent instanceof PointToPointIntent) {
                                root = context.codec(PointToPointIntent.class).encode((PointToPointIntent) intent, context);
                            } else if (intent instanceof SinglePointToMultiPointIntent) {
                                root = context.codec(SinglePointToMultiPointIntent.class).encode((SinglePointToMultiPointIntent) intent, context);
                            } else if (intent instanceof MultiPointToSinglePointIntent) {
                                root = context.codec(MultiPointToSinglePointIntent.class).encode((MultiPointToSinglePointIntent) intent, context);
                            } else {
                                root = context.codec(Intent.class).encode(intent, context);
                            }

                            String intentStr = root.toString();

                            out.println("length:" + intentStr.length());
                            out.write(intentStr.getBytes(), 0, intentStr.length());
                        }

                    } else {
                        out.println("error:Unsupported command: " + command);
                    }

                    out.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                    out.println("error:" + e.getMessage());
                    out.flush();
                }
            }
        }
    }
}
