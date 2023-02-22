package edu.purdue.cs.pursec.ifuzzer.net.topo.impl;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.TestConstants;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.criterion.impl.SelectorGenerator;
import edu.purdue.cs.pursec.ifuzzer.fuzz.intent.impl.TopologyIntentGuidance;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.*;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoElem.State;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoOperation.Type;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import org.projectfloodlight.openflow.types.IPAddress;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;

public class TopoMatrix {
    private static final Logger log = LoggerFactory.getLogger(TopoMatrix.class);
    boolean isInit;
    String [] vertexId;
    TopoNode[] vertices;
    Map<String, Integer> idToMatrix;
    Map<Integer, Integer> hostToDp;
    String [][][] matrix;
    int [] nextPortOfDevice;
    int topoHostSize, topoDeviceSize;
    int srcX, srcY, dstX, dstY;
    boolean [][] tested;
    boolean selectorEnabled;
    SelectorGenerator generator;
    List<TopoOperation> appliedTopoOperations;
    // TODO: get reserved mac addresses from test-agent
    List<String> reservedMacAddr;

    public TopoMatrix() {
        appliedTopoOperations = new ArrayList<>();
    }

    public TopoMatrix copy() {
        TopoMatrix newMatrix = new TopoMatrix();
        newMatrix.appliedTopoOperations.addAll(this.appliedTopoOperations);
        return newMatrix;
    }

    public void initialize(TopoGraph topoGraph) {
        // rows and columns have commutative property
        Set<TopoNode> vertexSet = topoGraph.getAllNodes().stream()
                .filter(k -> State.ACTIVE.equals(k.getState()))
                .collect(Collectors.toSet());
        matrix = new String[2][vertexSet.size()][vertexSet.size()];
        tested = new boolean[vertexSet.size()][vertexSet.size()];
        vertexId = new String[vertexSet.size()];
        vertices = new TopoNode[vertexSet.size()];
        nextPortOfDevice = new int[vertexSet.size()];
        idToMatrix = new HashMap<>();
        hostToDp = new HashMap<>();
        generator = new SelectorGenerator();
        reservedMacAddr = new ArrayList<>();
        srcX = srcY = dstX = dstY = -1;

        // i for host, j for device
        int i = 0, j = vertexSet.size() - 1;
        for (TopoNode vertex : vertexSet) {
            if (vertex instanceof TopoHost) {
                vertexId[i] = vertex.getId();
                vertices[i] = vertex;
                idToMatrix.put(vertex.getId(), i);

                TopoHost topoHost = (TopoHost) vertex;
                if (topoHost.getAddr() != null)
                    reservedMacAddr.add(topoHost.getAddr());
                i ++;

            } else if (vertex instanceof TopoDevice) {

                vertexId[j] = vertex.getId();
                vertices[j] = vertex;
                nextPortOfDevice[j] = 1;
                idToMatrix.put(vertex.getId(), j);
                j --;

            } else {
                /* unexpected */
                assert(false);
            }
        }

        assert(i > j);
        topoHostSize = i;
        topoDeviceSize = vertexSet.size() - i;

        Set<TopoEdge> activeEdges = topoGraph.getAllEdges().stream()
                .filter(k -> State.ACTIVE.equals(k.getState()))
                .collect(Collectors.toSet());
        for (TopoEdge edge : activeEdges) {
            int srcIdx = idToMatrix.getOrDefault(edge.getSrcId(), -1);
            int dstIdx = idToMatrix.getOrDefault(edge.getDstId(), -1);

            if (srcIdx < 0 || dstIdx < 0)
                continue;

            // support unidirectional path
            matrix[0][srcIdx][dstIdx] = edge.getSrcPort();
            matrix[1][srcIdx][dstIdx] = edge.getDstPort();

            if (edge.getSrcPort() != null) {
                int nextSrcPort = Integer.parseInt(edge.getSrcPort()) + 1;
                if (nextPortOfDevice[srcIdx] < nextSrcPort)
                    nextPortOfDevice[srcIdx] = nextSrcPort;
            } else {
                // edge.getSrcPort() == null
                hostToDp.put(srcIdx, dstIdx);
            }

            if (edge.getDstPort() != null) {
                int nextDstPort = Integer.parseInt(edge.getDstPort()) + 1;
                if (nextPortOfDevice[dstIdx] < nextDstPort)
                    nextPortOfDevice[dstIdx] = nextDstPort;
            } else {
                hostToDp.put(dstIdx, srcIdx);
            }
        }

        isInit = true;
    }

    public boolean isInit() {
        return isInit;
    }

    public void setInit(boolean isInit) {
        this.isInit = isInit;
    }

    private JsonObject createPointJson(String deviceId, String portId) {
        JsonObject pointJson = new JsonObject();
        pointJson.addProperty("device", deviceId);
        pointJson.addProperty("port", portId);

        return pointJson;
    }

    private int[] getValidPoint(int d, int x, int y) {
        assert(x >= topoHostSize && x < vertexId.length);
        assert(y >= topoHostSize && y < vertexId.length);
        int [] idx = new int[2];

        do {
            y++;
            if (y >= vertexId.length) {
                x++;
                y = 0;
                if (x >= vertexId.length) {
                    idx[0] = vertexId.length;
                    idx[1] = vertexId.length;
                    return idx;
                }
            }
        } while (matrix[d][x][y] == null);

        idx[0] = x;
        idx[1] = y;

        return idx;
    }

    private int[] getRandomValidPoint(int d) {
        int [] idx = new int[2];
        Random rand = TopologyIntentGuidance.random;
        int x, y;
        int diffLen = vertexId.length - topoHostSize;
        do {
            x = rand.nextInt(diffLen) + topoHostSize;
            y = rand.nextInt(diffLen) + topoHostSize;
        } while (matrix[d][x][y] == null);

        idx[0] = x;
        idx[1] = y;

        return idx;
    }

    public JsonObject getRandomPointToPointIntent(JsonObject targetJson) {
        int[] srcIdx = getRandomValidPoint(0);
        int[] dstIdx = getRandomValidPoint(1);
        if (ConfigConstants.CONFIG_DISABLE_SAME_POINTS_OF_P2P_INTENT) {
            while ((srcIdx[0] == dstIdx[1]) && (srcIdx[1] == dstIdx[0])) {
                dstIdx = getRandomValidPoint(1);
            }
        }

        targetJson.add("ingressPoint",
                createPointJson(vertexId[srcIdx[0]], matrix[0][srcIdx[0]][srcIdx[1]]));
        targetJson.add("egressPoint",
                createPointJson(vertexId[dstIdx[1]], matrix[1][dstIdx[0]][dstIdx[1]]));

        if (selectorEnabled) {
//            boolean singleSelector = FuzzUtil.rand.nextBoolean();
            targetJson.add("selector", generator.randomSelector(1));
//                    singleSelector ? 1 : FuzzUtil.rand.nextInt(49) + 1));
        }

        return targetJson;
    }

    public JsonObject getNextPointToPointIntent(JsonObject targetJson) throws EndFuzzException {
        if (srcX < 0) {
            srcX = srcY = dstX = dstY = 0;
            int[] srcIdx = getValidPoint(0, srcX, srcY);
            srcX = srcIdx[0];
            srcY = srcIdx[1];
        }

        if (srcX >= vertexId.length) {
            if (!ConfigConstants.CONFIG_ENABLE_SELECTOR)
                throw new EndFuzzException();

            selectorEnabled = true;
            srcX = srcY = dstX = dstY = 0;
            int[] srcIdx = getValidPoint(0, srcX, srcY);
            srcX = srcIdx[0];
            srcY = srcIdx[1];
        }

        // get next index
        int[] dstIdx = getValidPoint(1, dstX, dstY);
        dstX = dstIdx[0];
        dstY = dstIdx[1];
        if (dstIdx[0] >= vertexId.length) {
            int[] srcIdx = getValidPoint(0, srcX, srcY);
            if (srcIdx[0] >= vertexId.length) {
                if (!ConfigConstants.CONFIG_ENABLE_SELECTOR)
                    throw new EndFuzzException();

                selectorEnabled = true;
                srcX = srcY = dstX = dstY = 0;
                srcIdx = getValidPoint(0, srcX, srcY);
            }

            srcX = srcIdx[0];
            srcY = srcIdx[1];

            dstIdx = getValidPoint(1, 0, 0);
            dstX = dstIdx[0];
            dstY = dstIdx[1];
        }

        // TODO: get random port
        // Point to Point -> select two devices, then select port between them.
        targetJson.add("ingressPoint",
                createPointJson(vertexId[srcX], matrix[0][srcX][srcY]));
        targetJson.add("egressPoint",
                createPointJson(vertexId[dstY], matrix[1][dstX][dstY]));

        if (selectorEnabled) {
//            boolean singleSelector = FuzzUtil.rand.nextBoolean();
            targetJson.add("selector", generator.randomSelector(1));
//                    singleSelector ? 1 : FuzzUtil.rand.nextInt(49) + 1));
        }

        return targetJson;
    }

    public JsonObject getRandomHostToHostIntent(JsonObject targetJson) {
        Random rand = TopologyIntentGuidance.random;

        int srcIdx = rand.nextInt(topoHostSize);
        int dstIdx = rand.nextInt(topoHostSize);
        targetJson.addProperty("one", vertexId[srcIdx]);
        targetJson.addProperty("two", vertexId[dstIdx]);
        if (ConfigConstants.CONFIG_ENABLE_H2H_HINT_FIELD) {
            int srcDp = hostToDp.getOrDefault(srcIdx, -1);
            int dstDp = hostToDp.getOrDefault(dstIdx, -1);

            if (srcDp < 0) {
                log.warn("Cannot find dp of {}", srcIdx);

            } else if (dstDp < 0) {
                log.warn("Cannot find dp of {}", dstIdx);

            } else {
                log.debug("add hint for H2H {}/{}:{} -> {}/{}:{}",
                        vertexId[srcIdx], vertexId[srcDp], matrix[0][srcDp][srcIdx],
                        vertexId[dstIdx], vertexId[dstDp], matrix[0][dstDp][dstIdx]);

                targetJson.add("_one",
                        createPointJson(vertexId[srcDp], matrix[0][srcDp][srcIdx]));
                targetJson.add("_two",
                        createPointJson(vertexId[dstDp], matrix[0][dstDp][dstIdx]));
            }
        }

        if (selectorEnabled) {
//            boolean singleSelector = FuzzUtil.rand.nextBoolean();
            targetJson.add("selector", generator.randomSelector(1));
//                    singleSelector ? 1 : FuzzUtil.rand.nextInt(49) + 1));
        }

        return targetJson;
    }

    public JsonObject getNextHostToHostIntent(JsonObject targetJson) throws EndFuzzException {
        if (srcX < 0) {
            srcX = dstX = 0;

            if (srcX >= topoHostSize)
                throw new EndFuzzException();

        } else {
            if (srcX >= topoHostSize) {
                if (!ConfigConstants.CONFIG_ENABLE_SELECTOR)
                    throw new EndFuzzException();

                selectorEnabled = true;
                srcX = 0;
                dstX = -1;
            }

            // get next index
            dstX++;

            if (dstX >= topoHostSize) {
                srcX++;
                dstX = 0;                       // permutation
                //dstX = srcX + 1;              // OR combination
                if (srcX >= topoHostSize) {
                    if (!ConfigConstants.CONFIG_ENABLE_SELECTOR)
                        throw new EndFuzzException();

                    selectorEnabled = true;
                    srcX = 0;
                }
            }
        }

        targetJson.addProperty("one", vertexId[srcX]);
        targetJson.addProperty("two", vertexId[dstX]);

        if (ConfigConstants.CONFIG_ENABLE_H2H_HINT_FIELD) {
            int srcDp = hostToDp.getOrDefault(srcX, -1);
            int dstDp = hostToDp.getOrDefault(dstX, -1);

            if (srcDp < 0) {
                log.warn("Cannot find dp of {}", srcX);

            } else if (dstDp < 0) {
                log.warn("Cannot find dp of {}", dstX);

            } else {
                log.debug("add hint for H2H {}/{}:{} -> {}/{}:{}",
                        vertexId[srcX], vertexId[srcDp], matrix[0][srcDp][srcX],
                        vertexId[dstX], vertexId[dstDp], matrix[0][dstDp][dstX]);

                targetJson.add("_one",
                        createPointJson(vertexId[srcDp], matrix[0][srcDp][srcX]));
                targetJson.add("_two",
                        createPointJson(vertexId[dstDp], matrix[0][dstDp][dstX]));
            }
        }

        if (selectorEnabled) {
//            boolean singleSelector = FuzzUtil.rand.nextBoolean();
            targetJson.add("selector", generator.randomSelector(1));
//                    singleSelector ? 1 : FuzzUtil.rand.nextInt(49) + 1));
        }

        return targetJson;
    }

    public String[] getAllHostIds() {
        return Arrays.stream(vertexId, 0, topoHostSize)
            .toArray(String[]::new);
    }

    public String[] getAllDeviceIds() {
        return Arrays.stream(vertexId, vertexId.length - topoDeviceSize, vertexId.length)
                .toArray(String[]::new);
    }

    private final int RANDOM_TOPO_DEVICE = 0;
    private final int RANDOM_TOPO_HOST = 1;
    private final int RANDOM_TOPO_LINK = 2;
    private final int RANDOM_TOPO_MAX = 3;

    public List<TopoOperation> getDiffTopoOperations(TopoMatrix curMatrix) {
        // TODO: (IMPORTANT) consider topology configuration (FIXME)
        return FuzzUtil.getDiffTopoOperations(curMatrix.appliedTopoOperations, this.appliedTopoOperations);
    }

    public TopoOperation getRandomTopoOperation() {
        TopoOperation topoOperation = null;
        Random rand = TopologyIntentGuidance.random;

        int randomTarget = rand.nextInt(RANDOM_TOPO_MAX);

        if (topoHostSize == vertexId.length) {
            // No more devices -> add device
            randomTarget = RANDOM_TOPO_DEVICE;
        } else if (topoHostSize + 1 == vertexId.length) {
            // Single device -> cannot add link
            randomTarget = rand.nextInt(RANDOM_TOPO_LINK);
        }

        if (randomTarget == RANDOM_TOPO_LINK) {
            boolean isDelete = rand.nextBoolean();

            // TODO: optimize performance
            if (isMatrixFull(topoHostSize, vertexId.length)) {
                isDelete = true;
            } else if (isMatrixEmpty(topoHostSize, vertexId.length)) {
                isDelete = false;
            }

            int srcIdx, dstIdx;
            String srcPort, dstPort;
            while (true) {
                srcIdx = rand.nextInt(topoDeviceSize) + topoHostSize;
                dstIdx = rand.nextInt(topoDeviceSize) + topoHostSize;

                if (srcIdx == dstIdx)
                    continue;

                if (isDelete && matrix[0][srcIdx][dstIdx] != null) {
                    // target for deleting
                    srcPort = matrix[0][srcIdx][dstIdx];
                    dstPort = matrix[1][srcIdx][dstIdx];
                    break;

                } else if (!isDelete && matrix[0][srcIdx][dstIdx] == null) {
                    // target for adding
                    srcPort = String.valueOf(nextPortOfDevice[srcIdx]++);
                    dstPort = String.valueOf(nextPortOfDevice[dstIdx]++);
                    break;
                }
            }

            TopoLink link = new TopoLink(vertexId[srcIdx], vertexId[dstIdx],
                    srcPort, dstPort);

            topoOperation = new TopoOperation(isDelete ? Type.DELETE : Type.ADD, link);

        } else if (randomTarget == RANDOM_TOPO_DEVICE) {
            boolean isDelete = rand.nextBoolean();
            Set<Integer> disconnMembers = getDisconnMember(0, vertexId.length).stream()
                    .filter(k -> k >= topoHostSize)
                    .collect(Collectors.toSet());

            // There is no device to be deleted.
            if (isDelete && disconnMembers.size() == 0) {
                isDelete = false;
            }

            if (isDelete) {
                int targetIdx = rand.nextInt(disconnMembers.size());
                Integer [] disconnMemberArr = new Integer[disconnMembers.size()];
                disconnMembers.toArray(disconnMemberArr);

                int target = disconnMemberArr[targetIdx];
                TopoDevice device = new TopoDevice(vertexId[target]);

                topoOperation = new TopoOperation(Type.DELETE, device);

            } else {
                String dpid = null;
                while (dpid == null) {
                    dpid = FuzzUtil.randomValidDpid(true, rand);
                    for (int i = topoHostSize; i < vertexId.length; i++) {
                        if (dpid.equals(vertexId[i])) {
                            dpid = null;
                            break;
                        }
                    }
                }

                TopoDevice device = new TopoDevice(dpid);
                topoOperation = new TopoOperation(Type.ADD, device);
            }

        } else if (randomTarget == RANDOM_TOPO_HOST) {
            boolean isDelete = rand.nextBoolean();
            if (topoHostSize < 2) {
                // Less than two hosts are meaningless
                isDelete = false;
            } else if (ConfigConstants.CONFIG_FUZZING_HOST_IN_SUBNET) {
                IPv4AddressWithMask subnet = IPv4AddressWithMask.of(TestConstants.TEST_DATA_SUBNET);
                int limitSize = subnet.getMask().not().getInt() + 1;
                if (topoHostSize >= limitSize)
                    isDelete = true;
            }

            if (isDelete) {

                int targetIdx = rand.nextInt(topoHostSize);
                int deviceIdx = -1;

                for (int i = topoHostSize; i < vertexId.length; i++) {
                    if (matrix[0][i][targetIdx] != null) {
                        deviceIdx = i;
                        break;
                    }
                }

                assert(deviceIdx >= 0);

                topoOperation = new TopoOperation(Type.DELETE, vertices[targetIdx],
                        vertexId[deviceIdx], matrix[0][deviceIdx][targetIdx]);
            } else {
                String randIp = null;
                while (randIp == null) {
                    randIp = FuzzUtil.randomIp(TestConstants.TEST_DATA_SUBNET, rand);

                    for (int i = 0; i < topoHostSize; i++) {
                        TopoHost topoHost = (TopoHost) vertices[i];
                        for (IPAddress ip : topoHost.getIps()) {
                            if (ip.toString().equals(randIp)) {
                                // exists
                                randIp = null;
                                break;
                            }
                        }

                        // exists
                        if (randIp == null)
                            break;
                    }
                }

                // generate randMac except reserved
                String randMac = FuzzUtil.randomMacAddress(true, rand);
                while (reservedMacAddr.contains(randMac)) {
                    randMac = FuzzUtil.randomMacAddress(true, rand);
                }
                TopoHost topoHost = new TopoHost(randIp, randMac);
                int randDeviceIdx = topoHostSize + rand.nextInt(topoDeviceSize);
                topoOperation = new TopoOperation(Type.ADD, topoHost,
                        vertexId[randDeviceIdx], String.valueOf(nextPortOfDevice[randDeviceIdx] ++));
            }
        }

        return topoOperation;
    }

    public List<TopoOperation> getAppliedTopoOperations() {
        return appliedTopoOperations;
    }

    public boolean addTopoOperation(TopoOperation topoOperation) {
        return appliedTopoOperations.add(topoOperation);
    }

    public boolean addTopoOperations(Collection<TopoOperation> topoOperation) {
        return appliedTopoOperations.addAll(topoOperation);
    }

    public boolean updateTopoOperation(TopoOperation oldOperation, TopoOperation newOperation) {
        int idx = appliedTopoOperations.indexOf(oldOperation);
        if (idx < 0)
            return false;

        appliedTopoOperations.set(idx, newOperation);
        return true;
    }

    /** Private Functions **/

    private boolean setEdgeIntoMatrix(TopoEdge edge) {
        int srcIdx = idToMatrix.getOrDefault(edge.getSrcId(), -1);
        int dstIdx = idToMatrix.getOrDefault(edge.getDstId(), -1);

        if (srcIdx < 0 || dstIdx < 0)
            return false;

        // support unidirectional path
        matrix[0][srcIdx][dstIdx] = edge.getSrcPort();
        matrix[1][srcIdx][dstIdx] = edge.getDstPort();

        return true;
    }

    private boolean isMatrixEmpty(int start, int end) {
        for (int i = 0; i < 2; i++) {
            for (int j = start; j < end; j++) {
                for (int k = start; k < end; k++) {
                    if (j == k)
                        continue;

                    if (matrix[i][j][k] != null)
                        return false;
                }
            }
        }

        return true;
    }

    private boolean isMatrixFull(int start, int end) {
        for (int i = 0; i < 2; i++) {
            for (int j = start; j < end; j++) {
                for (int k = start; k < end; k++) {
                    if (j == k)
                        continue;

                    if (matrix[i][j][k] == null)
                        return false;
                }
            }
        }

        return true;
    }

    private Set<Integer> getDisconnMember(int start, int end) {
        Set<Integer> disconnMembers = new HashSet<>();

        // 1. select member [start, end)
        for (int j = start; j < end; j++) {
            boolean skip = false;

            // 2. find whether there is connected member except itself
            for (int k = start; k < end; k++) {
                if (j == k)
                    continue;

                // 3. find both ways
                if (matrix[0][j][k] != null || matrix[1][j][k] != null) {
                    skip = true;
                    break;
                }

                if (matrix[0][k][j] != null || matrix[1][k][j] != null) {
                    skip = true;
                    break;
                }
            }

            if (!skip)
                disconnMembers.add(j);
        }

        return disconnMembers;
    }
}
