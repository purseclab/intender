package edu.purdue.cs.pursec.ifuzzer.fuzz.packet.impl;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.api.TestConstants;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion;
import edu.purdue.cs.pursec.ifuzzer.criterion.api.Criterion.Type;
import edu.purdue.cs.pursec.ifuzzer.criterion.impl.IPCriterion;
import edu.purdue.cs.pursec.ifuzzer.fuzz.api.EndFuzzException;
import edu.purdue.cs.pursec.ifuzzer.fuzz.packet.api.FuzzPacketGuidance;
import edu.purdue.cs.pursec.ifuzzer.fuzz.packet.api.TestIntent;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.Box;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.Rule;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.VerifyRuleId;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.FlowRuleStore;
import edu.purdue.cs.pursec.ifuzzer.net.flow.impl.ReachabilityTree;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.*;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.searchservice.PathServer;
import edu.purdue.cs.pursec.ifuzzer.util.FuzzUtil;
import edu.purdue.cs.pursec.ifuzzer.util.ONOSUtil;
import jdd.bdd.BDD;
import org.apache.commons.net.util.SubnetUtils;
import org.apache.thrift.TException;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class PazzPacketGuidance implements FuzzPacketGuidance {
    private static Logger log = LoggerFactory.getLogger(PazzPacketGuidance.class);
    private static final String BITS = "01";
    private static final int BITS_LENGTH = BITS.length();
    private final Random rand = new Random();
    private PathServer pathServer = new PathServer();
    private ReachabilityTree reachabilityTree;
    private Map<VerifyRuleId, Rule> flowRules;
    private BDD bdd;
    private static final TopoGraph topoGraph = TopoGraph.getOperationalTopology();
    private static final FlowRuleStore flowRuleStore = FlowRuleStore.getInstance();
    private TestIntent testH2HIntent;
    private List<TestIntent> testIntentList = new ArrayList<>();
    private int pointListIdx;
    private static Map<Integer, List<String>> dstIPAddrList;
    private static Map<Integer, Integer> dstIPAddrIndices;
    private static Map<Integer, JsonObject> testJsonCache;

    public PazzPacketGuidance() {
        // Do not test intent 1 by 1
        ConfigConstants.CONFIG_ENABLE_TEST_EACH_ERROR_INTENT = false;
    }

    @Override
    public void init() {
        //this.reachabilityTree = reachabilityTree;
        this.testH2HIntent = null;
        this.testIntentList.clear();
        this.pointListIdx = -1;
        dstIPAddrList = new ConcurrentHashMap<>();
        dstIPAddrIndices = new ConcurrentHashMap<>();
        testJsonCache = new ConcurrentHashMap<>();

        // generate reachability Tree
        // TODO: Why PAZZ calculate R.T. twice?
        reachabilityTree = new ReachabilityTree(flowRuleStore.getNetworkGraph(), flowRuleStore.getInverseNetworkGraph(),
                flowRuleStore.getFlowRules(), flowRuleStore.getInRuleList(), flowRuleStore.getBoxes(), ConfigConstants.CONFIG_PAZZ_PACKET_HEADER_LEN);
        this.bdd = reachabilityTree.getBDD();
        this.flowRules = reachabilityTree.getNetworkRules();

        // NOTE: execute PathServer!
        pathServer.initialize(flowRuleStore);
    }

    @Override
    public synchronized void removeTestIntent(TestIntent testIntent) {
        ReachabilityIntent intent = testIntent.getIntent();
        if (intent instanceof HostToHostIntent) {
            testH2HIntent = null;
        } else {
            // normally removeTestIntent is called right after addTestIntent
            testIntentList.remove(testIntent);
        }
    }

    @Override
    public synchronized void addTestIntent(TestIntent testIntent) {
        ReachabilityIntent intent = testIntent.getIntent();
        if (intent instanceof HostToHostIntent) {
            testH2HIntent = testIntent;
            return;
        }

        int idx = testIntentList.size();
        testIntentList.add(testIntent);
        PointToPointIntent p2pIntent = (PointToPointIntent)intent;
        ResourcePoint srcPoint = p2pIntent.getSrc();
        ResourcePoint dstPoint = p2pIntent.getDst();

        int reachableHS = reachabilityTree.getHeaderSpace(srcPoint, dstPoint);
        //System.out.print("Reachable HS: ");
        //bdd.printSet(reachableHS);
        try {
            // test the hidden Rules for every inPort and outPort in the Lists
            dstIPAddrList.put(idx, new ArrayList<>());
            testHiddenRules(idx);
            log.info("{}: {} IPs are generated: {}:{} -> {}:{}", idx + 1,
                    dstIPAddrList.get(idx).size(),
                    srcPoint.getDeviceId(), srcPoint.getPortNo(),
                    dstPoint.getDeviceId(), dstPoint.getPortNo());
            dstIPAddrIndices.put(0, 0);

        } catch (IOException | InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Override
    public List<TestIntent> getTestIntents() {
        return this.testIntentList;
    }

    @Override
    public synchronized JsonObject getRandomPacketJson() throws EndFuzzException {
        if (testIntentList.size() == 0) {
            if (testH2HIntent == null)
                return null;
            return testH2HIntent.getIntent().toTestJson(topoGraph);
        }

        /* main */
        int pointSetNum = testIntentList.size();
        int doneCnt = 0;
        while (true) {
            pointListIdx = (pointListIdx + 1) % pointSetNum;

            int innerDstIPAddrIdx = dstIPAddrIndices.computeIfAbsent(pointListIdx, k -> 0);
            List<String> dstIPAddrs = dstIPAddrList.get(pointListIdx);

            if (dstIPAddrs.size() > innerDstIPAddrIdx) {
                String dstIP = dstIPAddrs.get(innerDstIPAddrIdx);
                dstIPAddrIndices.put(pointListIdx, innerDstIPAddrIdx + 1);
                return getTestJson(pointListIdx, dstIP);

            } else if (doneCnt < pointSetNum) {
                doneCnt += 1;

            } else {
                // Done
                if (ConfigConstants.CONFIG_PACKET_FUZZING_TIMEOUT == 0) {
                    log.info("finished");
                    throw new EndFuzzException("End Fuzz");
                }

                // Or reset
                pointListIdx = -1;
                dstIPAddrIndices = new ConcurrentHashMap<>();
            }
        }
    }

    @Override
    public JsonObject getValidTestJson(ReachabilityIntent intent) {
        IPv4AddressWithMask dstIP = null;

        JsonObject testJson = intent.toTestJson(topoGraph);
        if (testJson == null)
            return null;

        // TODO: reset metadata of PAZZ
        List<Criterion> criteria = intent.getCriteriaList();
        for (Criterion criterion : criteria) {
            if (criterion.type().equals(Type.IPV4_DST)) {
                IPCriterion ipCriterion = (IPCriterion) criterion;
                dstIP = ipCriterion.ip();
                break;
            }
        }

        if (dstIP != null)
            testJson.addProperty("dst", FuzzUtil.randomIp(dstIP, rand));

        testJson.addProperty("sflow", true);
        testJson.addProperty("wait_sec", ConfigConstants.CONFIG_PACKET_FUZZING_TIMEOUT);

        return testJson;
    }

    private JsonObject getTestJson(int pointListIdx, String dstIP) {
        if (testJsonCache.containsKey(pointListIdx)) {
            JsonObject testJson = testJsonCache.get(pointListIdx);
            testJson.addProperty("dst", dstIP);
            return testJson;
        }

        TestIntent targetIntent = testIntentList.get(pointListIdx);
        ResourcePoint srcPoint = (ResourcePoint) targetIntent.getIntent().getSrc();
        ResourcePoint dstPoint = (ResourcePoint) targetIntent.getIntent().getDst();

        JsonObject jsonObject = new JsonObject();
        jsonObject.addProperty("key", targetIntent.getKey());
        jsonObject.addProperty("ret_url", TestConstants.TEST_MANAGER_URL + TestConstants.TEST_RET_ROUTE);

        // SRC/DST -> packet addr, SENDER/RECEIVER -> position (host addr or dp/port)
        jsonObject.addProperty("src", "10.0.0.1");     // TODO: set source?
        jsonObject.addProperty("dst", dstIP);

        JsonArray sendersJson = new JsonArray();
        sendersJson.add(srcPoint.getDeviceId() + "/" + srcPoint.getPortNo());
        jsonObject.add("senders", sendersJson);

        JsonArray receiversJson = new JsonArray();
        receiversJson.add(dstPoint.getDeviceId() + "/" + dstPoint.getPortNo());
        jsonObject.add("receivers", receiversJson);

        JsonArray jsonArray = new JsonArray();
        JsonObject criterionJson = new JsonObject();
        criterionJson.addProperty("type", "IP_PROTO");
        criterionJson.addProperty("protocol", 6);
        jsonArray.add(criterionJson);
        jsonObject.add("criteria", jsonArray);

        jsonObject.addProperty("sflow", true);
        jsonObject.addProperty("cnt", 5);
        jsonObject.addProperty("wait_sec", ConfigConstants.CONFIG_PACKET_FUZZING_TIMEOUT);

        // XXX
        jsonObject.addProperty("ethDst", "10:22:33:44:55:66");

        testJsonCache.put(pointListIdx, jsonObject);

        return jsonObject;
    }

    private void testHiddenRules(int idx) throws IOException, InterruptedException {
        TestIntent targetIntent = testIntentList.get(idx);
        ResourcePoint inPoint = (ResourcePoint) targetIntent.getIntent().getSrc();
        ResourcePoint outPoint = (ResourcePoint) targetIntent.getIntent().getDst();
        //from within all the boxes available on the network declare the "inBox" and "outBox" boxes
        long startTime = System.nanoTime(); //starting the timer

        long inDpid = ONOSUtil.getDpid(inPoint.getDeviceId());
        long outDpid = ONOSUtil.getDpid(outPoint.getDeviceId());
        int inPort = Integer.parseInt(inPoint.getPortNo());
        int outPort = Integer.parseInt(outPoint.getPortNo());;

        Box inBox = flowRuleStore.getBoxes().get(inDpid);
        Box outBox = flowRuleStore.getBoxes().get(outDpid);
        //Get all inBox rules that have inPort as in_port
        List<VerifyRuleId> inRuleList = inBox.findInportToRuleMapping(inPort);
        //Get all outBox rules that have outPort as out_port
        List<VerifyRuleId> outRuleList = outBox.findRuleToPortMapping(outPort);

        int inPortPredicate = bdd.getZero();//initiate inPortPredicate ass BDD "0"
        //loop through all inRuleList rules
        for (VerifyRuleId ruleId: inRuleList){
            Rule inRule = flowRules.get(ruleId);
            //Union of all inRules predicates to get the header space coverage of inBox
            inPortPredicate = bdd.or(inPortPredicate, inRule.getPredicates()[inPort%10]);
        }

        int outPortPredicate = bdd.getZero();//initiate outPortPredicate ass BDD "0"
        for(VerifyRuleId ruleId: outRuleList){//loop through all outRuleList rules
            Rule outRule = flowRules.get(ruleId);
            int outRule_Predicate = 0;
            //since the predicates are related to in_port not out_port
            //we have to go through rule.predicates[7] to get the predicate related to that rule
            for(int j =1; j<7;j++) {
                if (outRule.getPredicates()[j] != 0) {
                    outRule_Predicate = outRule.getPredicates()[j];
                }
            }
            ////Union of all outRules predicates to get the header space coverage of outBox
            outPortPredicate = bdd.or(outPortPredicate, outRule_Predicate);//outRule.getPredicates()[outPort%10]
        }
        //Calculate the difference between outBox HS and inBox HS
        int diffHS = diff(outPortPredicate,inPortPredicate);
        //System.out.println("Diff HS: " + diffHS);
        long stopTime = System.nanoTime();//stopping the timer
        long elapsedTime = stopTime - startTime;
        double seconds = (double)elapsedTime / 1000000000.0;
        System.out.printf("%d-th intent Fuzz Calculation time: %f\n", idx, seconds);
        //System.out.println("Final inPortPredicate: "+ convertBDDToString(bdd,inPortPredicate));
        //System.out.println("Final outPortPredicate: "+ convertBDDToString(bdd,outPortPredicate));
        //System.out.println("The diffHeader Space: "+ convertBDDToString(bdd,diffHS));
        //Based on the difference, if != 0 generate fuzz traffic in the diff HS "sweepTest"
        if(diffHS != 0 ){
            sweepTest(idx, diffHS);
            diffHS = outPortPredicate;
        }
        else{
            diffHS = diff(inPortPredicate, outPortPredicate);
            //System.out.println("Diff HS if previous is Sinput>Soutput: " + convertBDDToString(bdd,diffHS));
            if(diffHS != 0){
                sweepTest(idx, diffHS);
            }
            diffHS = inPortPredicate;
        }
        //After testing the difference we randomly generate fuzz traffic in the uncovered header space area
        try {
            int uncovered = bdd.ref(diff(bdd.getOne(),diffHS));
            if (uncovered != 0)
                randomTest(idx, uncovered);
        } catch (TException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    private int diff(int a, int b) {
        //int diff = bdd.and(b, (bdd.not(bdd.and(b, a)))); //ORIGINAL
        int diff = bdd.ref(bdd.and(a, (bdd.not(bdd.and(a, b)))));
        return diff;
    }

    private void randomTest(int idx, int hs) throws TException, IOException, InterruptedException {
        String stringHS = convertBDDToString(bdd, hs);
        for (String line: stringHS.split("\\n")){
            //System.out.println("Random Test NBTB received Header: " + line);
            for (int i=0; i<8; i++) {
                char[] newStringHS = line.toCharArray();
                Random rand = new Random();
                newStringHS[i] = BITS.charAt(rand.nextInt(BITS_LENGTH));
                String wildcard = new String(newStringHS);
                //-------------send(wildcard);
                //System.out.println("Random Test NBTB sent IP: " + ip );
                dstIPAddrList.get(idx).addAll(Arrays.asList(toIP(wildcard)));
            }
        }
        for (String line: stringHS.split("\\n")) {
            char[] newStringHS = line.toCharArray();
            if (newStringHS[26] == '1') {
                newStringHS[26] = '0';
            }
            else {
                newStringHS[26] = '1';
            }
            String wildcard = new String(newStringHS);
            //System.out.println("Random Test NBSTB received header: " + line);
            //System.out.println("Random Test NBSTB sent IP: " + ip );
            dstIPAddrList.get(idx).addAll(Arrays.asList(toIP(wildcard)));

            //----------------send(wildcard);
        }
    }

    private void sweepTest(int idx, int hs) throws IOException, InterruptedException{
        String stringHS = convertBDDToString(bdd, hs);
        for (String line: stringHS.split("\\n")) {
            //System.out.println("Sweep Test received Header: " + line);
            //System.out.println("Sweep Test result IP: " + ip );
            dstIPAddrList.get(idx).addAll(Arrays.asList(toIP(line)));
        }
    }

    private String convertBDDToString(BDD bdd, int hs) {
        // Create a stream to hold the output
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        // IMPORTANT: Save the old System.out!
        PrintStream old = System.out;
        // Tell Java to use the special stream
        System.setOut(ps);
        // Print the BDD: goes to the special stream
        bdd.printSet(hs);
        // Put things back
        System.out.flush();
        System.setOut(old);

        return baos.toString();
    }

    private String[] toIP(String header) {

        String ip_address ="";
        int mask = 0;
        int start = 0, end = 8;
        int[] addr = new int[4];

        for (int i = 0; i < 4; i++) {
            String addr_substring = header.substring(start,end);
            if(start != 24) {
                addr_substring = addr_substring.replaceAll("-", "0");
                addr[i] = Integer.parseInt(addr_substring, 2);
                if(i == 0) {
                    if (addr[i] < 127) {mask = 8;}
                    else if (addr[i] < 191 && addr[i] >= 128) {mask = 16;}
                    else mask = 24;
                }
            }
            else {
                mask = 32 - (addr_substring.length() - addr_substring.replace("-", "").length());
                addr_substring = addr_substring.replaceAll("-", "0");
                addr[i] = Integer.parseInt(addr_substring, 2);
            }
            start += 8;
            end += 8;
        }
        ip_address = addr[0] + "." + addr[1] + "." + addr[2] + "." + addr[3];

        SubnetUtils utils = new SubnetUtils(ip_address + "/" + mask);

        return utils.getInfo().getAllAddresses();
    }
}
