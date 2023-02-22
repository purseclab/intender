package edu.purdue.cs.pursec.ifuzzer.util;

import com.google.gson.*;
import edu.purdue.cs.pursec.ifuzzer.IFuzzer;
import edu.purdue.cs.pursec.ifuzzer.api.ONOSConstants;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.Box;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.Rule;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.FlowRuleStore;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentType;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.ONOSIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.*;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.*;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoElem.State;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import org.jacoco.core.tools.ExecDumpClient;
import org.jacoco.core.tools.ExecFileLoader;
import org.projectfloodlight.openflow.types.MacAddress;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

public class ONOSUtil {
    private static Logger log = LoggerFactory.getLogger(ONOSUtil.class);
    private static final Properties properties;
    private static int MAC_LEN = MacAddress.NONE.toString().length();

    static {
        Properties fallback = new Properties();
        fallback.put("key", "default");
        properties = new Properties(fallback);

        URL url = ONOSUtil.class.getClassLoader().getResource(ONOSConstants.ONOS_PROP_NAME);
        if (url == null) throw new UncheckedIOException(new FileNotFoundException(ONOSConstants.ONOS_PROP_NAME));

        try (InputStream is = url.openStream()) { properties.load(is); }
        catch (IOException e) { throw new UncheckedIOException("Failed to load resource", e); }
    }

    public static JsonObject createNewContentJson() {
        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("controller", "onos");
        return jsonObject;
    }

    public static String getHostId(String hostId) {
        if (!isValidHostId(hostId))
            return hostId;

        return hostId.substring(0, MAC_LEN + 1).toUpperCase() + hostId.substring(MAC_LEN + 1);
    }

    public static boolean isValidHostId(String hostId) {
        try {
            // (1) check mac address
            String macString = hostId.substring(0, MAC_LEN);
            MacAddress.of(macString);

            // (2) check vlan ID
            String postString = hostId.substring(MAC_LEN + 1);
            if (postString.toLowerCase().equals("none"))
                return true;
            else if (postString.toLowerCase().equals("any"))
                return true;
            else {
                int vlan = Integer.parseInt(postString);
                if (vlan >= -2 && vlan <= 4096)
                    return true;
            }
        } catch (Exception e) {
            return false;
        }

        return false;
    }

    public static String getLinkId(String srcId, String dstId, String srcPort, String dstPort) {
        if (srcId == null)
            srcId = "";
        if (srcPort == null)
            srcPort = "";
        if (dstId == null)
            dstId = "";
        if (dstPort == null)
            dstPort = "";

        return (srcId + '/' + srcPort + ' ' + dstId + '/' + dstPort);
    }

    public static boolean isEqualDpid(String srcId, String dstId) {
        if (srcId.equals(dstId))
            return true;

        if (srcId.startsWith("of:") && dstId.startsWith("of:")) {
            // DPID is case-insensitive
            if (srcId.toLowerCase().equals(dstId.toLowerCase()))
                return true;
        }

        return false;
    }

    public static String toDpid(@Nonnull String dpid) {
        if (!dpid.startsWith("of:"))
            return dpid;

        return dpid.toLowerCase();
    }

    public static long getDpid(@Nonnull String dpid) {
        if (dpid.startsWith("of:")) {
            return Long.parseLong(dpid.substring("of:".length()), 16);
        }
        return Long.parseLong(dpid, 16);
    }

    public static String getDpid(long dpid) {
        return String.format("of:%016x", dpid);
    }

    public static String getONOSVersion() {
        return properties.getProperty(ONOSConstants.ONOS_SERVER_VERSION);
    }

    public static String getONOSMethodListFilePath() {
        return IFuzzer.rootPath + File.separator + properties.getProperty(ONOSConstants.ONOS_METHOD_LIST_FILE_PATH);
    }

    public static String getONOSClassListFilePath() {
        return IFuzzer.rootPath + File.separator + properties.getProperty(ONOSConstants.ONOS_CLASS_LIST_FILE_PATH);
    }

    public static String getONOSClasspathListFilePath() {
        return IFuzzer.rootPath + File.separator + properties.getProperty(ONOSConstants.ONOS_CLASSPATH_LIST_FILE_PATH);
    }

    public static String getONOSClassContextListFilePath() {
        return IFuzzer.rootPath + File.separator + properties.getProperty(ONOSConstants.ONOS_CLASS_CONTEXT_LIST_FILE_PATH);
    }

    public static String getONOSRestServerURL(String ipAddress, String port, String prefix) {
        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.append("http://").append(ipAddress).append(":").append(port).append(prefix);
        return urlBuilder.toString().replaceAll("\\s+", "");
    }

    public static String getONOSRestServerURL(String ipAddress, String port, String prefix, String postfix) {
        StringBuilder urlBuilder = new StringBuilder();
        urlBuilder.append("http://").append(ipAddress).append(":").append(port).append(prefix).append("/").append(postfix);
        return urlBuilder.toString().replaceAll("\\s+", "");
    }

    public static String getDevicesFromONOS() throws IOException {
        return getRestFromONOS("devices");
    }

    public static String getLinksFromONOS() throws IOException {
        return getRestFromONOS("links");
    }

    public static String getHostsFromONOS() throws IOException {
        return getRestFromONOS("hosts");
    }

    public static String getIntentsFromONOS() throws IOException {
        return getRestFromONOS("intents");
    }

    public static String getIntentFromONOS(Intent intent) throws IOException {
        String prefix = "intents/" + intent.getAppId() + "/" + intent.getKey();
        return getRestFromONOS(prefix);
    }

    public static String getIntentFromONOS(String appId, String key) throws IOException {
        String prefix = "intents/" + appId + "/" + key;
        return getRestFromONOS(prefix);
    }

    public static String getFlowRulesFromONOS() throws IOException {
        return getRestFromONOS("flows");
    }

    private static String getRestFromONOS(String object) throws IOException {
        String url = ONOSUtil.getONOSRestServerURL(
                properties.getProperty(ONOSConstants.ONOS_SERVER_ADDR),
                properties.getProperty(ONOSConstants.ONOS_SERVER_PORT),
                properties.getProperty(ONOSConstants.ONOS_SERVER_PREFIX),
                object);

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("GET");

        String auth = properties.getProperty(ONOSConstants.ONOS_SERVER_UNAME) + ":" +
                properties.getProperty(ONOSConstants.ONOS_SERVER_PWD);
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        conn.setRequestProperty("Authorization", "Basic " + encodedAuth);

        int responseCode = conn.getResponseCode();
        if (responseCode >= 200 && responseCode < 300) {
            String response = "";
            Scanner scanner = new Scanner(conn.getInputStream());
            while(scanner.hasNextLine()){
                response += scanner.nextLine();
                response += "\n";
            }
            scanner.close();
            return response;
        }

        System.out.printf("GET://%s Response Code: %d\n", object, responseCode);
        return null;
    }

    public static HttpURLConnection setIntentToONOS(ONOSIntent intent) throws IOException {
        String onosVersion = properties.getProperty(ONOSConstants.ONOS_SERVER_VERSION);
        return setIntentToONOS(intent.toJson(onosVersion).toString());
    }

    public static HttpURLConnection setIntentToONOS(String intentStr) throws IOException {

        log.debug(intentStr);

        String url = ONOSUtil.getONOSRestServerURL(
                properties.getProperty(ONOSConstants.ONOS_SERVER_ADDR),
                properties.getProperty(ONOSConstants.ONOS_SERVER_PORT),
                properties.getProperty(ONOSConstants.ONOS_SERVER_PREFIX),
                "intents");

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("POST");

        String auth = properties.getProperty(ONOSConstants.ONOS_SERVER_UNAME) + ":" +
                properties.getProperty(ONOSConstants.ONOS_SERVER_PWD);
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        conn.setRequestProperty("Authorization", "Basic " + encodedAuth);

        conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        conn.setRequestProperty("Accept", "application/json");
        conn.setDoOutput(true);

        OutputStream os = conn.getOutputStream();
        if (intentStr != null)
            os.write(intentStr.getBytes("utf-8"));
        os.close();

        return conn;
    }

    public static HttpURLConnection delIntentToONOS(String appId, String key) throws IOException {
        String onosVersion = properties.getProperty(ONOSConstants.ONOS_SERVER_VERSION);

        String url = ONOSUtil.getONOSRestServerURL(
                properties.getProperty(ONOSConstants.ONOS_SERVER_ADDR),
                properties.getProperty(ONOSConstants.ONOS_SERVER_PORT),
                properties.getProperty(ONOSConstants.ONOS_SERVER_PREFIX),
                "intents/" + appId + "/" + key);

        // Request Device REST
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("DELETE");

        String auth = properties.getProperty(ONOSConstants.ONOS_SERVER_UNAME) + ":" +
                properties.getProperty(ONOSConstants.ONOS_SERVER_PWD);
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        conn.setRequestProperty("Authorization", "Basic " + encodedAuth);

        return conn;
    }

    public static HttpURLConnection delIntentToONOS(ONOSIntent intent) throws IOException {
        return delIntentToONOS(intent.getAppId(), intent.getKey());
    }

    // TODO: change in host & hostEdge
    public static void storeGraph(TopoGraph topoGraph, String message) {
        JsonObject jObject = TestUtil.fromJson(message);
        if (jObject.has("devices")) {
            // store devices
            JsonArray jDevices = jObject.get("devices").getAsJsonArray();
            jDevices.forEach(k -> topoGraph.addNode(new TopoDevice(k.getAsJsonObject())));
        } else if (jObject.has("hosts")) {
            // store hosts
            JsonArray jHosts = jObject.get("hosts").getAsJsonArray();

            Set<TopoHost> toBeRemovedHosts = topoGraph.getAllHosts(true);
            log.debug("Store hosts: {} in graph, {} in rest", toBeRemovedHosts.size(),
                    jHosts.size());

            for (JsonElement jHostElem : jHosts) {
                // store hosts (that are all active)
                JsonObject jHost = jHostElem.getAsJsonObject();
                TopoHost host = new TopoHost(jHost);
                TopoHost storeHost = (TopoHost) topoGraph.getNode(host.getId());
                toBeRemovedHosts.remove(storeHost);

                // store hostEdges
                if (jHost.get("locations") != null) {
                    // ONOS-2.4.0
                    JsonArray jLocations = jHost.get("locations").getAsJsonArray();
                    /* NOTES: do not allow multiple locations */
                    for (JsonElement jLocElem : jLocations) {
                        JsonObject jLoc = jLocElem.getAsJsonObject();
                        if (jLoc.get("elementId") == null)
                            continue;
                        if (jLoc.get("port") == null)
                            continue;

                        String deviceId = jLoc.get("elementId").getAsString();
                        String port = jLoc.get("port").getAsString();

                        /* If device port is used by host or link, do not add this port */
                        if (topoGraph.getEdgeFromSrc(deviceId, port) == null &&
                                topoGraph.getEdgeFromDst(deviceId, port) == null) {
                            topoGraph.addEdge(new TopoHostEdge(deviceId, host.getId(), port, null));
                            topoGraph.addEdge(new TopoHostEdge(host.getId(), deviceId, null, port));
                        } else {
                            host = null;
                        }
                    }
                } else if (jHost.get("location") != null) {
                    // ONOS-1.9.0
                    JsonObject jLoc = jHost.get("location").getAsJsonObject();
                    if (jLoc.get("elementId") != null && jLoc.get("port") != null) {
                        String deviceId = jLoc.get("elementId").getAsString();
                        String port = jLoc.get("port").getAsString();
                        /* If device port is used by host or link, do not add this port */
                        if (topoGraph.getEdgeFromSrc(deviceId, port) == null &&
                                topoGraph.getEdgeFromDst(deviceId, port) == null) {
                            topoGraph.addEdge(new TopoHostEdge(deviceId, host.getId(), port, null));
                            topoGraph.addEdge(new TopoHostEdge(host.getId(), deviceId, null, port));
                        } else {
                            host = null;
                        }
                    }
                }

                if (host != null) {
                    if (storeHost == null || !storeHost.compare(host)) {
                        topoGraph.addNode(host);
                    } else if (State.INACTIVE.equals(storeHost.getState())) {
                        topoGraph.updateStateNode(State.ACTIVE, host);
                    }
                }
            }


            // Remove not found hosts
            TopoEdge edge;
            for (TopoHost removedHost : toBeRemovedHosts) {
                log.info("Remove Host: {}", removedHost.toJson().toString());
                edge = topoGraph.getEdgeFromSrc(removedHost.getId(), null);
                topoGraph.removeHostEdge((TopoHostEdge) edge);              // host -> dp
                edge = topoGraph.getEdgeFromDst(removedHost.getId(), null);
                topoGraph.removeHostEdge((TopoHostEdge) edge);              // dp -> host
                topoGraph.removeHost(removedHost);                          // host
            }

        } else if (jObject.has("links")) {
            JsonArray jLinks = jObject.get("links").getAsJsonArray();
            jLinks.forEach(k -> topoGraph.addEdge(new TopoLink(k.getAsJsonObject())));
        }
    }

    public static ONOSIntent getIntentFromJson(String jsonObjectStr) throws JsonSyntaxException, JsonIOException, IOException {
        return getIntentFromJson(TestUtil.fromJson(jsonObjectStr));
    }

    public static ONOSIntent getIntentFromJson(JsonObject jObject) throws IOException {
        if (!jObject.has("type"))
            return null;

        ONOSIntent intent = null;
        String type = jObject.get("type").getAsString();
        if (type.equals(IntentType.PointToPointIntent.toString())) {
            intent = PointToPointIntent.of(jObject);
        } else if (type.equals(IntentType.SinglePointToMultiPointIntent.toString())) {
            intent = SinglePointToMultiPointIntent.of(jObject);
        } else if (type.equals(IntentType.MultiPointToSinglePointIntent.toString())) {
            intent = MultiPointToSinglePointIntent.of(jObject);
        } else if (type.equals(IntentType.HostToHostIntent.toString())) {
            intent = HostToHostIntent.of(jObject);
        }

        if (intent != null && intent.getState() == null && jObject.has("state")) {
            log.warn("unsupported state: {}", jObject.get("state").toString());
        }

        return intent;
    }

    public static void storeIntent(IntentStore intentStore, String message) throws JsonSyntaxException, JsonIOException {
        JsonObject jsonObject = TestUtil.fromJson(message);
        if (jsonObject.has("intents")) {
            // store devices
            JsonArray jIntents = jsonObject.get("intents").getAsJsonArray();
            jIntents.forEach(k -> storeIntent(intentStore, k.getAsJsonObject()));
        }
    }

    private static boolean storeIntent(IntentStore intentStore, JsonObject jsonObject) {
        Intent intent;
        try {
            intent = getIntentFromJson(jsonObject);
            if (intent == null)
                return false;
        } catch (Exception e) {
            return false;
        }

        // NOTE: key of intentStore (used by scenario) != key of intent
        intentStore.initIntent(intent.getKey(), intent);

        return true;
    }

    public static boolean storeFlowRule(FlowRuleStore flowRuleStore, String message)
            throws JsonSyntaxException, JsonIOException {
        JsonObject jsonObject = TestUtil.fromJson(message);
        if (!jsonObject.has("flows"))
            return false;

        JsonArray jFlows = jsonObject.get("flows").getAsJsonArray();

        // TODO: optimize performance in reset flow rules
        flowRuleStore.cleanUp();
        flowRuleStore.init();

        List<Rule> flowRuleList = StreamSupport.stream(jFlows.spliterator(), true)
                .map(k -> getFlowRuleFromJson(flowRuleStore, k.getAsJsonObject()))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        // add rule into global list
        flowRuleStore.storeFlowRules(flowRuleList);

        return true;
    }

    private static Rule getFlowRuleFromJson(FlowRuleStore flowRuleStore, JsonObject jsonObject) {
        // generate rule first
        Rule rule = Rule.of(jsonObject);

        // set Predicates
        if (rule != null && rule.getMatchString() != null) {
            int rulePredicate = flowRuleStore.getIntPredicate(rule.getMatchString());
            for (int portIndex : rule.getin_ports()) {
                rule.setPredicateForPort(portIndex % 10, rulePredicate);
            }
        }

        return rule;
    }

    public static ExecFileLoader dumpCoverage(boolean isReset) throws NumberFormatException, IOException {
        // DUMP
        ExecDumpClient client = new ExecDumpClient() {
            protected void onConnecting(InetAddress address, int port) {
                System.out.printf("[INFO] Connecting to %s:%s.%n", address, port);
            }

            protected void onConnectionFailure(IOException exception) {
                System.err.printf("[WARN] %s.%n", exception.getMessage());
            }
        };
        client.setReset(isReset);
        client.setRetryCount(10);
        ExecFileLoader loader = client.dump(properties.getProperty(ONOSConstants.ONOS_SERVER_ADDR),
                Integer.parseInt(properties.getProperty(ONOSConstants.ONOS_SERVER_JACOCO_PORT)));

        return loader;
    }
}
