package edu.purdue.cs.pursec.ifuzzer.fuzz.intent.api;

import com.google.gson.JsonArray;
import com.google.gson.JsonIOException;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.internal.GeometricDistribution;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzScenario;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import javassist.bytecode.ByteArray;
import org.junit.Assume;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;

public class IntentJsonGenerator extends Generator<JsonObject> {

    private static GeometricDistribution geometricDistribution =
            new GeometricDistribution();

    /** Mean number of members for each JSON element. */
    private static final double MEAN_NUM_MEMBERS = 4;

    /** Mean number of fields for each JSON element. */
    private static final double MEAN_NUM_FIELDS = 4;

    protected final int maxDepth = 2;

    private Generator<String> stringGenerator = new AlphaStringGenerator();

    public IntentJsonGenerator() {
        super(JsonObject.class);
    }

    /**
     * Generators a random JSON document.
     * @param random a source of pseudo-random values
     * @param status generation state
     * @return a randomly-generated JSON document
     */
    @Override
    public JsonObject generate(SourceOfRandomness random, GenerationStatus status) {
        JsonObject jsonObject = new JsonObject();

        if (stringGenerator == null) {
            stringGenerator = gen().type(String.class);
        }

        try {
            if (ZestIntentGuidanceConfigs.CONFIG_ENABLE_INTENT_FORMATTED_GEN)
                populateIntentJson(jsonObject, random, status);
            else
                populateJson(jsonObject, random, status, 0);
        } catch (JsonParseException e) {
            Assume.assumeNoException(e);
        }
        return jsonObject;

    }

    private String makeString(SourceOfRandomness random, GenerationStatus status) {
        return stringGenerator.generate(random, status);
    }

    private JsonObject populateJson(JsonObject jsonObject, SourceOfRandomness random, GenerationStatus status, int depth) {
        int numFields = Math.max(0, geometricDistribution.sampleWithMean(MEAN_NUM_FIELDS, random)-1);
        for (int i = 0; i < numFields; i++) {
            String key = makeString(random, status);
            if (depth < maxDepth && random.nextBoolean()) {
                // add jsonObject
                JsonObject childJson = new JsonObject();
                populateJson(childJson, random, status, depth+1);
                jsonObject.add(key, childJson);
            } else if (random.nextBoolean()) {
                // add text
                jsonObject.addProperty(key, makeString(random, status));
            } else if (random.nextBoolean()) {
                // add number
                jsonObject.addProperty(key, random.nextInt());
            } else if (random.nextBoolean()) {
                // add boolean
                jsonObject.addProperty(key, random.nextBoolean());
            } else if (random.nextBoolean()) {
                // add JsonArrays
                JsonArray childrenArray = new JsonArray();
                int numMembers = Math.max(0, geometricDistribution.sampleWithMean(MEAN_NUM_MEMBERS, random)-1);
                if (depth < maxDepth && random.nextBoolean()) {
                    // add jsonObject
                    for (int j = 0; j < numMembers; j++)
                        childrenArray.add(populateJson(jsonObject, random, status, depth+1));
                } else if (random.nextBoolean()) {
                    for (int j = 0; j < numMembers; j++)
                        childrenArray.add(makeString(random, status));
                } else if (random.nextBoolean()) {
                    for (int j = 0; j < numMembers; j++)
                        childrenArray.add(random.nextInt());
                } else if (random.nextBoolean()) {
                    for (int j = 0; j < numMembers; j++)
                        childrenArray.add(random.nextBoolean());
                }
                jsonObject.add(key, childrenArray);
            }
        }

        return jsonObject;
    }

    private JsonObject populateIntentJson(JsonObject jsonObject, SourceOfRandomness random, GenerationStatus status) {
        // type
        boolean isP2P = random.nextBoolean();
        if (isP2P)
            jsonObject.addProperty("type", "PointToPointIntent");
        else
            jsonObject.addProperty("type", "HostToHostIntent");

        // appId
        if (random.nextBoolean()) {
            // NOTE: do we have to make correct appId?
            jsonObject.addProperty("appId", makeString(random, status));
        } else if (random.nextBoolean()) {
            jsonObject.addProperty("appId", "org.onosproject." + makeString(random, status));
        } else {
            jsonObject.addProperty("appId", "org.onosproject.null");
        }

        // (priority)
        if (random.nextBoolean()) {
            jsonObject.addProperty("priority", random.nextInt());
        }

        // (key)
        if (random.nextBoolean()) {
            jsonObject.addProperty("key", makeString(random, status));
        }

        // member
        if (isP2P) {
            // NOTE: do we have to make correct dpid?

            boolean isOFDevice = random.nextBoolean();
            JsonObject srcPoint = new JsonObject();
            srcPoint.addProperty("device", isOFDevice ? FuzzUtil.randomValidDpid(true, random) :
                    makeString(random, status));
            srcPoint.addProperty("port", isOFDevice ? String.valueOf(FuzzUtil.randomPortNo(random)) :
                    makeString(random, status));
            jsonObject.add("ingressPoint", srcPoint);

            JsonObject dstPoint = new JsonObject();
            dstPoint.addProperty("device", isOFDevice ? FuzzUtil.randomValidDpid(true, random) :
                    makeString(random, status));
            dstPoint.addProperty("port", isOFDevice ? String.valueOf(FuzzUtil.randomPortNo(random)) :
                    makeString(random, status));
            jsonObject.add("egressPoint", dstPoint);
        } else {
            // NOTE: do we have to make correct hostId?

            boolean isHostId = random.nextBoolean();
            jsonObject.addProperty("one", isHostId ? FuzzUtil.randomValidHostId(random) :
                    makeString(random, status));
            jsonObject.addProperty("two", isHostId ? FuzzUtil.randomValidHostId(random) :
                    makeString(random, status));
        }

        // other fields?
//        if (random.nextBoolean()) {
//            populateJson(jsonObject, random, status, 0);
//        }

        return jsonObject;
    }

    public boolean ejectIntentJson(JsonObject inputJson, ByteArrayOutputStream outputStream) throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);

        boolean isP2P = false;
        if (!inputJson.has("type")) {
            return false;
        } else {
            String type = inputJson.get("type").getAsString();
            if (type.equals("PointToPointIntent")) {
                // write true
                outputStream.write(1);
                isP2P = true;
            } else if (type.equals("HostToHostIntent")) {
                // write false
                outputStream.write(0);
            } else {
                return false;
            }
        }

        if (!inputJson.has("appId")) {
            return false;
        } else {
            String appId = inputJson.get("appId").getAsString();
            if (appId.equals("org.onosproject.null")) {
                // write false, false
                outputStream.write(0);
                outputStream.write(0);
            } else if (appId.startsWith("org.onosproject.")) {
                String appString = appId.substring("org.onosproject".length());
                // write false, true
                outputStream.write(0);
                outputStream.write(1);
                outputStream.write(appString.getBytes(StandardCharsets.UTF_8));
            } else {
                // write true
                outputStream.write(1);
                outputStream.write(appId.getBytes(StandardCharsets.UTF_8));
            }
        }

        if (!inputJson.has("priority")) {
            // write false
            outputStream.write(0);
        } else {
            int priority = inputJson.get("priority").getAsInt();
            // write true and integer
            outputStream.write(1);
            outputStream.write(byteBuffer.putInt(priority).array());
        }

        if (!inputJson.has("key")) {
            // write false
            outputStream.write(0);
        } else {
            String key = inputJson.get("key").getAsString();
            // write true and string
            outputStream.write(1);
            outputStream.write(key.getBytes(StandardCharsets.UTF_8));
        }

        // NOTE: we guarantee that all members of intent follow ONOS, OpenFlow grammar.
        // write true
        outputStream.write(1);

        // member
        if (isP2P) {
            if (!inputJson.has("ingressPoint") || !inputJson.has("egressPoint")) {
                return false;
            }

            JsonObject srcPoint = inputJson.get("ingressPoint").getAsJsonObject();
            if (!srcPoint.has("device") ||  !srcPoint.has("port"))
                return false;

            JsonObject dstPoint = inputJson.get("egressPoint").getAsJsonObject();
            if (!dstPoint.has("device") ||  !dstPoint.has("port"))
                return false;

            String srcDeviceId = srcPoint.get("device").getAsString();
            String srcPort = srcPoint.get("port").getAsString();
            String dstDeviceId = dstPoint.get("device").getAsString();
            String dstPort = dstPoint.get("port").getAsString();

            // eject FuzzUtil.randomValidDpid() & FuzzUtil.randomPortNo() for src
            FuzzUtil.ejectONOSDpid(srcDeviceId, outputStream);
            FuzzUtil.ejectPortNo(Long.parseLong(srcPort), outputStream);
            // eject FuzzUtil.randomValidDpid() & FuzzUtil.randomPortNo() for dst
            FuzzUtil.ejectONOSDpid(dstDeviceId, outputStream);
            FuzzUtil.ejectPortNo(Long.parseLong(dstPort), outputStream);

        } else {
            if (!inputJson.has("one") || !inputJson.has("two")) {
                return false;
            }

            String one = inputJson.get("one").getAsString();
            String two = inputJson.get("two").getAsString();

            // eject FuzzUtil.randomValidHostId()
            FuzzUtil.ejectHostId(one, outputStream);
            FuzzUtil.ejectHostId(two, outputStream);
        }

        return true;
    }
}
