package edu.purdue.cs.pursec.ifuzzer.util;

import com.google.gson.JsonObject;
import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.FastSourceOfRandomness;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.IntentJsonGenerator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.NonTrackingGenerationStatus;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api.StreamBackedRandom;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.ZestIntentGuidance.Input;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.ZestIntentGuidance.LinearInput;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.ZestIntentGuidance.SeedInput;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation;
import org.jacoco.core.data.ExecutionData;
import org.jacoco.core.tools.ExecFileLoader;
import org.projectfloodlight.openflow.types.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static java.util.Objects.hash;

public class FuzzUtil {
    private static Logger log = LoggerFactory.getLogger(FuzzUtil.class);
    public static Generator<JsonObject> generator = new IntentJsonGenerator();
    public static final Random rand = new Random();

    public static JsonObject getIntentJsonFromGenerator(String input) throws IOException {
        SeedInput seedInput = new SeedInput(input);
        InputStream inputStream = createParameterStream(seedInput);
        return getIntentJsonFromGenerator(inputStream);
    }

    public static JsonObject getIntentJsonFromGenerator(File file) throws IOException {
        SeedInput seedInput = new SeedInput(file);
        InputStream inputStream = createParameterStream(seedInput);
        return getIntentJsonFromGenerator(inputStream);
    }

    public static JsonObject getIntentJsonFromGenerator(Input input) throws IOException {
        InputStream inputStream = createParameterStream(input);
        return getIntentJsonFromGenerator(inputStream);
    }

    public static JsonObject getIntentJsonFromGenerator(InputStream inputStream) {
        StreamBackedRandom randomFile = new StreamBackedRandom(inputStream, Long.BYTES);
        SourceOfRandomness sourceOfRandomness = new FastSourceOfRandomness(randomFile);
        GenerationStatus genStatus = new NonTrackingGenerationStatus(sourceOfRandomness);

        return generator.generate(sourceOfRandomness, genStatus);
    }

    public static InputStream createParameterStream(Input currentInput) {
        // Return an input stream that reads bytes from a linear array
        return new InputStream() {
            int bytesRead = 0;

            @Override
            public int read() throws IOException {
                assert currentInput instanceof LinearInput : "ZestGuidance should only mutate LinearInput(s)";

                // For linear inputs, get with key = bytesRead (which is then incremented)
                LinearInput linearInput = (LinearInput) currentInput;
                // Attempt to get a value from the list, or else generate a random value
                int ret = linearInput.getOrGenerateFresh(bytesRead++, rand);
                // infoLog("read(%d) = %d", bytesRead, ret);
                return ret;
            }
        };
    }

    public static Input getZestInputFromIntentJson(String intentJsonStr) throws IOException {
        JsonObject intentJson = TestUtil.fromJson(intentJsonStr);

        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {

            if (!((IntentJsonGenerator) generator).ejectIntentJson(intentJson, outputStream)) {
                throw new IOException("fail to eject intentJson to random string");
            }

            // convert to ByteArrayInputStream
            return new SeedInput(outputStream.toByteArray());
        }
    }

    public static Byte[] getCoverageBitmaps(ExecFileLoader loader, int mapSize) {
        Byte[] traceBits = new Byte[mapSize];

        traceBits[0] = 1;
        for (int i = 1; i < mapSize; i++)
            traceBits[i] = 0;

        for (ExecutionData data : loader.getExecutionDataStore().getContents()) {
            int feedbackId = hash(data.getId()) % (mapSize - 1);
            if (feedbackId < 0)
                feedbackId += mapSize - 1;
            feedbackId += 1;

            for (boolean probe : data.getProbes()) {
                if (probe)
                    traceBits[feedbackId]++;
            }
        }
        return traceBits;
    }


    public static List<TopoOperation> getDiffTopoOperations(List<TopoOperation> prevList, List<TopoOperation> nextList) {
        List<TopoOperation> topoOperations = new ArrayList<>();

        log.debug("Get difference in topology operations between old({}) and new({})",
                prevList.size(), nextList.size());

        // Currently, curMatrix is applied in topology.
        int commonLen = 0;
        for (int i = 0; i < nextList.size(); i++) {

            if (i >= prevList.size())
                break;

            if (!nextList.get(i).typeEquals(prevList.get(i)))
                break;

            commonLen ++;
        }

        // 1) Revert applied operations of curMatrix
        if (commonLen < prevList.size()) {
            for (int i = prevList.size() - 1; i >= commonLen; i--) {
                topoOperations.add(prevList.get(i).invert());
            }
        }

        // 2) Add remaining operations of this matrix
        for (int i = commonLen; i < nextList.size(); i++) {
            topoOperations.add(nextList.get(i));
        }

        return topoOperations;
    }

    /**
     * random operations
     */
    public static JsonObject blackboxFuzzPoint(JsonObject pointJson, Random random) {
        if (pointJson.has("device")) {
            String deviceId = pointJson.get("device").getAsString();
            pointJson.addProperty("device", blackboxFuzzString(deviceId, random));
        }

        if (pointJson.has("port")) {
            String portId = pointJson.get("port").getAsString();
            boolean setPortNumber = random.nextBoolean();
            if (setPortNumber) {
                pointJson.addProperty("port", String.valueOf(randomPortNo(random)));
            } else {
                pointJson.addProperty("port", blackboxFuzzString(portId, random));
            }
        }

        return pointJson;
    }

    public static String blackboxFuzzString(String s, Random random) {
        int trials = 1;
        if (s.length() > 0)
            trials = random.nextInt(s.length()) + 1;

        for (int i = 0; i < trials; i++)
            s = mutateString(s, random);

        return s;
    }

    private static String mutateString(String s, Random random) {
        String newStr;

        int opr = random.nextInt(s.length() > 0 ? 3 : 1);
        switch (opr) {
            case 0:
                newStr = insertRandomChar(s, random);
                break;
            case 1:
                newStr = modifyRandomChar(s, random);
                break;
            case 2:
                newStr = deleteRandomChar(s, random);
                break;
            default:
                /* Unreachable... */
                newStr = s;
                break;
        }

        return newStr;
    }


    /**
     * random valid object operations
     */

    public static String randomValidHostId(Random random) {
        // [MAC] + [VLAN]
        String hostId = randomMacAddress(true, random);

        // ONOS neglects a middle character
        hostId += "/";

        hostId += randomVlanId(true, random);

        return hostId;
    }

    public static String randomValidHostId(SourceOfRandomness random) {
        // [MAC] + [VLAN]
        String hostId = randomMacAddress(true, random);

        // ONOS neglects a middle character
        hostId += "/";

        hostId += randomVlanId(true, random);

        return hostId;
    }

    public static void ejectHostId(String hostId, OutputStream outputStream) throws IOException {
        String macAddr = hostId.substring(0, "00:00:00:00:00:00".length());
        String vlanId = hostId.substring("00:00:00:00:00:00/".length());

        ejectMacAddress(macAddr, outputStream);
        ejectVlanIdForHost(vlanId, outputStream);
    }

    // TODO: support preferred port no in topology
    public static long randomPortNo(Random random) {
        long portNo;

        // Bound: [0, 0xffffff00]
        portNo = 0xffffffffL;
        while (portNo > 0xffffff00L) {
            portNo = random.nextLong() & 0xffffffffL;

            /* break, if port is reserved */
            if (portNo >= 0xfffffff8L)
                break;
        }

        return portNo;
    }

    public static long randomPortNo(SourceOfRandomness random) {
        long portNo;

        portNo = random.nextLong(0, 0xffffff00L + 8);
        if (portNo > 0xffffff00L) {
            portNo += 0xf7L;        /* ff8L ~ fffL */
        }

        return portNo;
    }

    public static void ejectPortNo(long portNo, OutputStream outputStream) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        long leftBytes = portNo >> Integer.SIZE;
        byteBuffer.putInt(0, (int)leftBytes);
        outputStream.write(byteBuffer.array());

        byteBuffer.putInt(0, (int)portNo);
        outputStream.write(byteBuffer.array());
    }

    public static String randomMacAddress(boolean isUnicast, Random random) {
        StringBuilder newStr = new StringBuilder();

        //[ ]:[ ]:[ ]:[ ]:[ ]:[ ]
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 2; j++) {
                char hex = randHexChar(random);

                if (isUnicast && i == 0 && j == 1) {
                    int base = Integer.parseInt(String.valueOf(hex), 16);
                    base &= 0xE;     // HEX & 1110
                    hex = Character.forDigit(base, 16);
                }

                newStr.append(hex);
            }
            if (i < 5)
                newStr.append(":");
        }

        return newStr.toString();
    }

    public static String randomMacAddress(boolean isUnicast, SourceOfRandomness random) {
        StringBuilder newStr = new StringBuilder();

        //[ ]:[ ]:[ ]:[ ]:[ ]:[ ]
        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 2; j++) {
                char hex = randHexChar(random);

                if (isUnicast && i == 0 && j == 1) {
                    int base = Integer.parseInt(String.valueOf(hex), 16);
                    base &= 0xE;     // HEX & 1110
                    hex = Character.forDigit(base, 16);
                }

                newStr.append(hex);
            }
            if (i < 5)
                newStr.append(":");
        }

        return newStr.toString();
    }

    public static void ejectMacAddress(String macAddr, OutputStream outputStream) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        for (int i = 0; i < 6; i++) {
            for (int j = 0; j < 2; j++) {
                char hex = macAddr.charAt((i * 3) + j);
                int idx = randHexCharToIdx(hex);

                byteBuffer.putInt(0, idx);
                outputStream.write(byteBuffer.array());
            }
        }
    }

    private static char randHexCharFromIdx(int idx) {
        char chr = 'a';

        if (idx < 0 || idx > 21)
            return chr;

        switch(idx / 6) {
            case 0:
                // 0-5: a-f
                chr = (char)('a' + (idx % 6));
                break;
            case 1:
                // 6-11: A-F
                chr = (char)('A' + (idx % 6));
                break;
            default:
                // 12-21 (remainder): 0-9
                chr = (char)('0' + idx - 12);
                break;
        }

        return chr;
    }

    private static int randHexCharToIdx(char hex) throws IOException {
        if (hex >= 'a' && hex <= 'f')
            return hex - 'a';
        else if (hex >= 'A' && hex <= 'F')
            return hex - 'A' + 6;
        else if (hex >= '0' && hex <= '9')
            return hex - '0' + 12;

        throw new IOException(String.format("Wrong hex char: %c", hex));
    }

    public static char randHexChar(Random random) {
        int idx = random.nextInt(22);
        return randHexCharFromIdx(idx);
    }

    public static char randHexChar(SourceOfRandomness random) {
        int idx = random.nextInt(22);
        return randHexCharFromIdx(idx);
    }

    public static String randAlphabets(int length, boolean allowUpper, Random random) {
        String str = "";

        for (int i = 0; i < length; i++) {
            int idx = random.nextInt(allowUpper ? 52 : 26);
            switch (idx / 26) {
                case 0:
                    // 0-25: a-z
                    str += (char) ('a' + (idx % 26));
                    break;
                case 1:
                    // 26-51: A-Z
                    str += (char) ('A' + (idx % 26));
                    break;
                default:
                    // unreachable ...
                    break;
            }
        }

        return str;
    }

    public static short randomEthType(boolean favored, Random random) {
        if (favored) {
            switch (random.nextInt(5)) {
                case 0:
                    return (short)EthType.IPv4.getValue();
                case 1:
                    return (short)EthType.ARP.getValue();
                case 2:
                    return (short)EthType.IPv6.getValue();
                case 3:
                    return (short)EthType.LLDP.getValue();
                case 4:
                    return (short)EthType.VLAN_FRAME.getValue();

                /* TODO: support others */
            }
            // unreachable ...
            return 0;
        } else {
            return (short) random.nextInt(0x10000);
        }
    }

    public static String randomVlanId(boolean isHostId, Random random) {
        int vlan;
        if (isHostId) {
            // vlan can be [-2, 4096]
            vlan = random.nextInt(4099) - 2;
        } else {
            // TODO: check range
            vlan = random.nextInt(4097);
        }

        if (vlan == -2)
            return "None";
        else if (vlan == -1)
            return "Any";
        else
            return String.valueOf(vlan);
    }

    public static String randomVlanId(boolean isHostId, SourceOfRandomness random) {
        int vlan;
        if (isHostId) {
            // vlan can be [-2, 4096]
            vlan = random.nextInt(4099) - 2;
        } else {
            // TODO: check range
            vlan = random.nextInt(4097);
        }

        if (vlan == -2)
            return "None";
        else if (vlan == -1)
            return "Any";
        else
            return String.valueOf(vlan);
    }

    public static void ejectVlanIdForHost(String vlanId, OutputStream outputStream) throws IOException {
        int vlan;

        if (vlanId.equals("None"))
            vlan = 0;
        else if (vlanId.equals("Any"))
            vlan = 1;
        else
            vlan = Integer.parseInt(vlanId) + 2;

        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        byteBuffer.putInt(vlan);
        outputStream.write(byteBuffer.array());
    }

    public static short randomIpProto(boolean favored, Random random) {
        if (favored) {
            switch (random.nextInt(4)) {
                case 0:
                    return IpProtocol.TCP.getIpProtocolNumber();
                case 1:
                    return IpProtocol.UDP.getIpProtocolNumber();
                case 2:
                    return IpProtocol.ICMP.getIpProtocolNumber();
                case 3:
                    return IpProtocol.SCTP.getIpProtocolNumber();

                /* TODO: support others */
            }

            // unreachable ...
            return 0;
        } else {
            return (short) random.nextInt(0x100);
        }
    }

    public static String randomIp(Random random) {
        StringBuilder ipStr = new StringBuilder();

        //[ ].[ ].[ ].[ ]
        for (int i = 0; i < 4; i++) {
            ipStr.append(random.nextInt(256));
            if (i < 3)
                ipStr.append(".");
        }

        return ipStr.toString();
    }

    public static String randomIp(String subnetStr, Random random) throws IllegalArgumentException {
        IPv4AddressWithMask subnet = IPv4AddressWithMask.of(subnetStr);
        return randomIp(subnet, random);
    }

    public static String randomIp(IPv4AddressWithMask subnet, Random random) {
        if (subnet.getMask().equals(IPv4Address.NO_MASK))
            return subnet.getValue().toString();
        IPv4Address subnetIp = subnet.getValue().and(subnet.getMask());
        int limit = subnet.getMask().not().getInt();
        int randRaw = random.nextInt(limit) + 1;

        return subnetIp.or(IPv4Address.of(randRaw)).toString();
    }

    public static String randomIpWithCidr(Random random) {
        while (true) {
            String ip = FuzzUtil.randomIp(random);
            int dstMask = random.nextInt(33);
            IPv4AddressWithMask subnet = IPv4AddressWithMask.of(String.format("%s/%d", ip, dstMask));
            IPv4Address subnetIp = subnet.getValue().and(subnet.getMask());
            if (!subnetIp.isUnspecified()) {
                return String.format("%s/%d", subnetIp.toString(), dstMask);
            }
        }
    }

    public static int randomTpPort(Random random) {
        return random.nextInt(0x10000);
    }

    public static String randomValidDpid(boolean isONOSValid, Random random) {
        // of:[16 length hex-integers]
        StringBuilder dpidStr = new StringBuilder("of:");

        for (int i = 0; i < 16; i++) {
            dpidStr.append(FuzzUtil.randHexChar(random));
        }

        if (isONOSValid)
            return dpidStr.toString().toLowerCase();

        return dpidStr.toString();
    }

    public static String randomValidDpid(boolean isONOSValid, SourceOfRandomness random) {
        // of:[16 length hex-integers]
        StringBuilder dpidStr = new StringBuilder("of:");

        for (int i = 0; i < 16; i++) {
            dpidStr.append(FuzzUtil.randHexChar(random));
        }

        if (isONOSValid)
            return dpidStr.toString().toLowerCase();

        return dpidStr.toString();
    }

    public static void ejectONOSDpid(String dpid, OutputStream outputStream) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        for (int i = 0; i < 16; i++) {
            char hex = dpid.charAt(i + 3);
            int idx = randHexCharToIdx(hex);

            byteBuffer.putInt(0, idx);
            outputStream.write(byteBuffer.array());
        }
    }

    /**
     * single-char operations
     */

    private static String insertRandomChar(String s, Random random) {
        String insChar = Character.toString((char)(32 + random.nextInt(95)));

        if (s == null || s.length() == 0)
            return insChar;

        int insPos = random.nextInt(s.length());
        return s.substring(0, insPos) + insChar + s.substring(insPos);
    }

    private static String deleteRandomChar(String s, Random random) {
        if (s == null || s.length() == 0)
            return s;

        int delPos = random.nextInt(s.length());      // [0, len)
        if (delPos == 0)
            return s.substring(1);                  // [1, len)
        else if (delPos == s.length() - 1)
            return s.substring(0, delPos - 1);      // [0, len - 1)

        return s.substring(0, delPos - 1) + s.substring(delPos + 1);
    }

    private static String modifyRandomChar(String s, Random random) {
        if (s == null || s.length() == 0)
            return s;

        String modChar = Character.toString((char)(32 + random.nextInt(95)));

        int modPos = random.nextInt(s.length());
        if (modPos == 0)
            return modChar + s.substring(1);                  // [1, len)
        else if (modPos == s.length() - 1)
            return s.substring(0, modPos - 1) + modChar;      // [0, len - 1)

        return s.substring(0, modPos - 1) + modChar + s.substring(modPos + 1);
    }
}
