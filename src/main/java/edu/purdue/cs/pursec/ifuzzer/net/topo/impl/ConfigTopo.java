package edu.purdue.cs.pursec.ifuzzer.net.topo.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public class ConfigTopo {
    private static final String ConfigJsonKeyTopo = "topo";
    private static final String ConfigJsonKeySwitch = "switch";
    private static final String ConfigJsonKeyHost = "host";
    private static final String [] configJsonKeys = {ConfigJsonKeyTopo, ConfigJsonKeySwitch, ConfigJsonKeyHost};

    Map<String, Boolean> deviceCheckList;
    Map<String, Boolean> linkCheckList;
    Map<String, Boolean> hostCheckList;
    Map<String, String> hostMacToId;
    String actionId;
    JsonObject configJson;
    int startTime;

    public ConfigTopo() {
        this.deviceCheckList = new HashMap<>();
        this.linkCheckList = new HashMap<>();
        this.hostCheckList = new HashMap<>();
        this.hostMacToId = new HashMap<>();
        this.actionId = null;
        this.configJson = null;
    }

    public static ConfigTopo next(ConfigTopo configTopo) {
        JsonObject configJson = configTopo.getConfigJson();
        if (configJson.has(ConfigJsonKeyTopo)) {
            if (configJson.get(ConfigJsonKeyTopo).getAsString().equals("fattree")) {
                assert (configJson.has(ConfigJsonKeySwitch));

                // Increase switch only
                int k = configJson.get(ConfigJsonKeySwitch).getAsInt();
                assert (k % 2 == 0);
                configJson.addProperty(ConfigJsonKeySwitch, k + 2);
            }
            // TODO: support other topologies
        }

        ConfigTopo newConfigTopo = new ConfigTopo();
        newConfigTopo.setConfig(configJson);
        return newConfigTopo;
    }

    public void setConfig(JsonObject jsonObject) {
        this.configJson = jsonObject;
    }

    public JsonObject getConfig() {
        return configJson;
    }

    /**
     * compareConfig()
     * @param jsonObject: {"topo": "__topo__", "switch": __switch__, "host": __host__}
     * @return
     */
    public boolean compareConfig(JsonObject jsonObject) {
        if (this.configJson == null)
            return false;

        for (String jsonKey : configJsonKeys) {
            if (!this.configJson.has(jsonKey) && !jsonObject.has(jsonKey)) {
                // Neither jsonObject has a value for the key
                continue;
            } else if (this.configJson.has(jsonKey) && jsonObject.has(jsonKey)) {
                // Both jsonObjects have a value for the key
                if (jsonKey.equals(ConfigJsonKeyTopo)) {
                    if (!this.configJson.get(jsonKey).getAsString().equals(jsonObject.get(jsonKey).getAsString()))
                        return false;
                } else {
                    if (this.configJson.get(jsonKey).getAsInt() != jsonObject.get(jsonKey).getAsInt())
                        return false;
                }
            } else {
                // One jsonObject has a value for the key, while the other doesn't.
                return false;
            }
        }

        return true;
    }

    public boolean checkDevice(String deviceId) {
        if (!deviceCheckList.containsKey(deviceId)) {
            deviceCheckList.put(deviceId, false);
            return false;
        }

        deviceCheckList.put(deviceId, true);
        return true;
    }

    public boolean checkLink(String srcId, String dstId, String srcPort, String dstPort) {
        return checkLink(ONOSUtil.getLinkId(srcId, dstId, srcPort, dstPort));
    }

    public boolean checkLink(String linkId) {
        if (!linkCheckList.containsKey(linkId)) {
            linkCheckList.put(linkId, false);
            return false;
        }

        linkCheckList.put(linkId, true);
        return true;
    }

    public boolean checkHost(String macAddress) {
        if (!hostCheckList.containsKey(macAddress)) {
            hostCheckList.put(macAddress, false);
            return false;
        }

        hostCheckList.put(macAddress, true);
        return true;
    }

    public boolean checkHost(String macAddress, String hostId) {
        hostMacToId.put(macAddress, hostId);
        return checkHost(macAddress);
    }

    public boolean removeHost(String macAddress) {
        hostMacToId.remove(macAddress);
        return hostCheckList.remove(macAddress);
    }

    public boolean areAllDevicesChecked() {
        if (deviceCheckList.size() == 0)
            return false;

        return (!(deviceCheckList.containsValue(false)));
    }

    public boolean areAllLinksChecked() {
        if (linkCheckList.size() == 0)
            return false;

        return (!(linkCheckList.containsValue(false)));
    }

    public boolean areAllHostsChecked() {
        if (hostCheckList.size() == 0)
            return false;

        return (!(hostCheckList.containsValue(false)));
    }

    public void clearAll() {
        configJson = null;
        deviceCheckList.clear();
        linkCheckList.clear();
        hostCheckList.clear();
        hostMacToId.clear();
    }

    public Set<String> getAllDevices() {
        return deviceCheckList.entrySet().stream()
                .filter(Entry::getValue)
                .map(Entry::getKey)
                .collect(Collectors.toSet());
    }

    public Set<String> getAllLinks() {
        return linkCheckList.entrySet().stream()
                .filter(Entry::getValue)
                .map(Entry::getKey)
                .collect(Collectors.toSet());
    }

    public Set<String> getAllHosts() {
        return hostCheckList.entrySet().stream()
                .filter(Entry::getValue)
                .map(Entry::getKey)
                .map(k -> hostMacToId.getOrDefault(k, null))
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());
    }

    public Set<String> getAllConfigHosts() {
        return hostCheckList.keySet();
    }

    public String getActionId() {
        return actionId;
    }

    public void setActionId(String actionId) {
        this.actionId = actionId;
    }

    public void setActionId(String actionId, int startTime) {
        this.actionId = actionId;
        this.startTime = startTime;
    }

    public int getStartTime() {
        return this.startTime;
    }

    public boolean isDone() {
        if (!areAllDevicesChecked())
            return false;
        if (!areAllLinksChecked())
            return false;
        if (!areAllHostsChecked())
            return false;

        return true;
    }

    public String getSummary() {
        String summary = "";

        int checkCnt = 0;
        for (boolean value : deviceCheckList.values()) {
            if (value)
                checkCnt ++;
        }
        summary += "DEVICES: (" + checkCnt + "/" + deviceCheckList.size() + ")";

        checkCnt = 0;
        for (boolean value : linkCheckList.values()) {
            if (value)
                checkCnt ++;
        }
        summary += ", LINKS: (" + checkCnt + "/" + linkCheckList.size() + ")";


        checkCnt = 0;
        for (boolean value : hostCheckList.values()) {
            if (value)
                checkCnt ++;
        }
        summary += ", HOSTS: (" + checkCnt + "/" + hostCheckList.size() + ")";

        return summary;
    }

    public JsonObject getConfigJson() {
        return this.configJson;
    }
}
