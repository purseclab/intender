package edu.purdue.cs.pursec.ifuzzer;

import com.google.gson.JsonObject;
import edu.purdue.cs.pursec.ifuzzer.api.ConfigConstants;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterface;
import edu.purdue.cs.pursec.ifuzzer.comm.api.IntentInterfaceResponse;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEvent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEvent.Type;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEventListener;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.HostToHostIntent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.impl.IntentStore;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoElem;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoGraphEvent;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoGraphListener;
import edu.purdue.cs.pursec.ifuzzer.scenario.impl.FuzzAction;
import edu.purdue.cs.pursec.ifuzzer.store.api.StoreListener;
import edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioEvent;
import edu.purdue.cs.pursec.ifuzzer.store.impl.ScenarioStore;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;

public class IntentDecisionService {
    private static Logger log = LoggerFactory.getLogger(IntentDecisionService.class);
    private final TopoGraph graph;
    private final IntentStore intentStore;
    private final ScenarioStore scenarioStore;
    private final IntentInterface intentInterface;

    public IntentDecisionService(TopoGraph graph, IntentStore intentStore,
                                 ScenarioStore scenarioStore, IntentInterface intentInterface) {
        this.graph = graph;
        this.intentStore = intentStore;
        this.scenarioStore = scenarioStore;
        this.intentInterface = intentInterface;

        intentStore.addListener(new InternalIntentListener());
        scenarioStore.addListener(new InternalScenarioListener());
    }

    public State getExpectedStateFromIntent(Intent intent) {
        if (intent.getState() != null &&
                !intent.getState().equals(State.INSTALLED) &&
                !intent.getState().equals(State.FAILED))
            return intent.getState();

        return TestUtil.getExpectedStateFromIntent(graph, intent);
    }

    /**
     * private classes for listeners
     */
    private static class InternalTopologyListener implements TopoGraphListener {
        @Override
        public void event(TopoGraphEvent event) {
            TopoElem elem = event.getElem();

            // TODO: recheck intents
        }
    }

    private class InternalIntentListener implements IntentEventListener, Runnable {
        private Map<IntentEvent, Integer> waitingEvents = new ConcurrentHashMap<>();
        ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
        Future future = null;
        private int curTimeCnt = 0;

        @Override
        public void event(IntentEvent event) {
            if (event.getType().equals(Type.CHECK_REQ)) {
                try {
                    // Try to get intent from ONOS and compare with given intent
                    if (checkIntentFromEvent(event, false))
                        return;

                } catch (IOException e) {
                    e.printStackTrace();
                    scenarioStore.failAction(event.getActionId(), event.getSeq(), e.getMessage());
                }

                waitingEvents.put(event, curTimeCnt);
                if (future == null)
                    future = executor.scheduleWithFixedDelay(this, 0,
                            ConfigConstants.CONFIG_INTENT_CHECK_INTERVAL_MS, TimeUnit.MILLISECONDS);
            }
        }

        /**
         * TODO:
         *  - run when the remaining intents exist
         *  - handle modified intent (check whether intent exists and content has changed)
          */
        @Override
        public void run() {
            curTimeCnt ++;
            if (waitingEvents.size() == 0)
                return;

            log.debug("[{}] # of intents: {}", curTimeCnt, waitingEvents.size());
            for (IntentEvent event : waitingEvents.keySet()) {
                int waitedTime = curTimeCnt - waitingEvents.get(event);
                log.debug("{} waited {} ms", event.getIntent().getKey(),
                        waitedTime * ConfigConstants.CONFIG_INTENT_CHECK_INTERVAL_MS);

                boolean isTimeout = (waitedTime >= ConfigConstants.CONFIG_INTENT_WAIT_TIMEOUT);

                // check it is wrong or not.
                try {
                    if (checkIntentFromEvent(event, isTimeout)) {
                        waitingEvents.remove(event);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                    waitingEvents.remove(event);
                    scenarioStore.failAction(event.getActionId(), event.getSeq(), e.getMessage());
                }
            }
        }

        /**
         * checkIntentFromEvent(): requests intent to controller and compares it with event
         *  [UNKNOWN] return false
         *  [KNOWN]
         *      [REQ]
         *          - before timeout, it returns false.
         *          - after timeout, it returns true.
         *              - with finishAction() in FAILED-expected case
         *                (only if ConfigConstants.CONFIG_ACCEPT_INSTALLING_AS_ERROR)
         *              - with failAction() in INSTALLED-expected case
         *      [INSTALLED -> INSTALLED / FAILED -> FAILED] return true with finishAction().
         *      [INSTALLED -> FAILED / FAILED -> INSTALLED] return true with failAction().
         * @param event, timeout
         * @return
         * @throws IOException
         */

        private boolean checkIntentFromEvent(IntentEvent event, boolean isTimeout) throws IOException {
            Intent reqIntent = event.getIntent();
            int seq = event.getSeq();

            IntentInterfaceResponse response = intentInterface.getIntent(reqIntent.getKey());
            Intent intent = response.getIntent();
            if (State.REMOVED.equals(reqIntent.getState())) {
                // check whether it is removed
                if (intent == null) {
                    scenarioStore.finishAction(event.getActionId(), seq, false,
                            State.REMOVED.toString(), reqIntent);
                    return true;
                } else if (!isTimeout) {
                    return false;
                } else {
                    // timeout
                    intentStore.updateIntent(event.getKey(), seq, intent.getState(), Type.CHECK_FAILED, event.getActionId());
                    scenarioStore.failAction(event.getActionId(), seq, "wrong state: " + intent.getState(),
                            true, intent);
                    return true;
                }
            }

            // Fail, if intent is not found except purge/remove requests
            if (intent == null) {
                log.warn("{} is not found in ONOS: {}", reqIntent.getKey(), response.getErrorMsg());

                if (isTimeout)
                    scenarioStore.failAction(event.getActionId(), seq, "timeout");

                return isTimeout;
            } else if (response.getErrorMsg() != null) {
                log.warn("error while getting intent: {}", response.getErrorMsg());

                if (isTimeout)
                    scenarioStore.failAction(event.getActionId(), seq, "timeout");

                return isTimeout;
            }

            State givenState = intent.getState();
            if (givenState == null) {
                log.warn("Unknown state");
                if (isTimeout)
                    scenarioStore.failAction(event.getActionId(), seq, "timeout: unknown state",
                            true, intent);
                return isTimeout;
            }

            State expectedState = getExpectedStateFromIntent(reqIntent);
            log.debug("[Intent Found] expected {} vs given {}",
                    expectedState.toString(), givenState.toString());

            // Req intent == Given intent
            if (reqIntent.equalsConfig(intent)) {
                if (expectedState.equals(givenState)) {
                    /* Success: given == expected */
                    intentStore.updateIntent(event.getKey(), seq, givenState, Type.CHECKED, event.getActionId());
                    scenarioStore.finishAction(event.getActionId(), seq, false,
                            expectedState.toString(), intent);
                    return true;

                } else if (isTimeout && ConfigConstants.CONFIG_ACCEPT_INSTALLING_AS_ERROR &&
                        expectedState.equals(State.FAILED) && givenState.equals(State.REQ)) {
                    if (intent instanceof HostToHostIntent) {
                        HostToHostIntent h2hIntent = (HostToHostIntent)intent;
                        if (h2hIntent.getSrc().getHostId().toLowerCase()
                                .equals(h2hIntent.getDst().getHostId().toLowerCase())) {
                            /* BUG4 */
                            intentStore.updateIntent(event.getKey(), seq, givenState, Type.CHECK_FAILED, event.getActionId());
                            scenarioStore.failAction(event.getActionId(), seq, "BUG4/wrong state: " + givenState,
                                    true, intent, ConfigConstants.STOPFUZZ_BUG4);
                            return true;
                        }
                    }

                    /* Success: REQ as FAILED */
                    intentStore.updateIntent(event.getKey(), seq, givenState, Type.CHECKED, event.getActionId());
                    scenarioStore.finishAction(event.getActionId(), seq, false, expectedState.toString(), intent);
                    return true;
                }
            }

            if (isTimeout) {
                /* TIMEOUT -> Failed */
                intentStore.updateIntent(event.getKey(), seq, givenState, Type.CHECK_FAILED, event.getActionId());
                scenarioStore.failAction(event.getActionId(), seq, "wrong state: " + givenState,
                        true, intent);
                return true;
            }

            /* Wait when the state is updated */
            log.warn("{} waits {} (cur: {})", intent.getKey(), reqIntent.toString(), intent.toString());
            return false;
        }
    }

    private class InternalScenarioListener implements StoreListener<ScenarioEvent> {
        @Override
        public void event(ScenarioEvent scenarioEvent) {
            if (scenarioEvent.getEventType().equals("APPLY")) {
                FuzzAction action = scenarioEvent.getAction();
                if (action.getActionCmd().equals("cp-verify-intent")) {
                    JsonObject content = action.getContent().getContent();
                    // TODO: error
                    if (!content.has("intentId"))
                        return;

                    intentStore.checkIntent(content.get("intentId").getAsString(),
                            scenarioEvent.getSeq(), action.getId());
                }
            }
        }
    }
}
