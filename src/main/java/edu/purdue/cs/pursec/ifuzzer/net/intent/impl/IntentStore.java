package edu.purdue.cs.pursec.ifuzzer.net.intent.impl;

import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.Intent.State;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEvent.Type;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEvent;
import edu.purdue.cs.pursec.ifuzzer.net.intent.api.IntentEventListener;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.util.TestUtil;

import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.stream.Collectors;

public class IntentStore {
    private Hashtable<String, Intent> intents;
    private final Set<IntentEventListener> listeners;

    public IntentStore() {
        this.listeners = new CopyOnWriteArraySet<IntentEventListener>();
        this.intents = new Hashtable<>();
    }

    public void addListener(IntentEventListener listener) {
        listeners.add(listener);
    }

    public Collection<Intent> getAllIntents() {
        return intents.values();
    }

    public Collection<Intent> getAllAliveIntents() {
        return intents.values().stream()
                .filter(k -> !State.REMOVED.equals(k.getState()))
                .collect(Collectors.toList());
    }

    public Collection<Entry<String, Intent>> getInstalledIntentEntries() {
        return intents.entrySet().stream()
                .filter(k -> State.INSTALLED.equals(k.getValue().getState()))
                .collect(Collectors.toList());
    }

    public Intent getIntent(String key) {
        return intents.get(key);
    }

    public String getKeyOfRandomIntent(Random random, boolean isAlive) {
        List<String> keyLists;
        if (isAlive) {
            keyLists = intents.entrySet().stream()
                    .filter(k -> !State.REMOVED.equals(k.getValue().getState()))
                    .map(Entry::getKey)
                    .collect(Collectors.toList());

        } else {
            keyLists = new ArrayList<>(intents.keySet());
        }

        if (keyLists.isEmpty())
            return null;

        return keyLists.get(random.nextInt(keyLists.size()));
    }

    public Map<String, Intent> getIntentsByState(State state) {
        return intents.entrySet().stream()
                .filter(k -> state.equals(k.getValue().getState()))
                .collect(Collectors.toMap(Entry::getKey, Entry::getValue));
    }

    public void clear() {
        intents.clear();
    }

    public void sendEvent(int seq, String actionId, Type type) {
        notifyListener(new IntentEvent(null, seq, null, actionId, type));
    }

    public void checkIntent(String key, int seq, String actionId) {
        Intent storedIntent = intents.get(key);
        if (storedIntent != null)
            notifyListener(new IntentEvent(key, seq, storedIntent, actionId, Type.CHECK_REQ));
    }

    public void testIntent(String key, int seq, String actionId) {
        Intent storedIntent = intents.get(key);
        if (storedIntent != null)
            notifyListener(new IntentEvent(key, seq, storedIntent, actionId, Type.TEST_REQ));
    }

    public void addIntent(String key, int seq, Intent intent, String actionId, boolean isNotifying) {
        intents.put(key, intent);
        if (isNotifying)
            notifyListener(new IntentEvent(key, seq, intent, actionId, Type.CHECK_REQ));
    }

    public void modIntent(String key, int seq, Intent intent, String actionId, boolean isNotifying) {
        intents.replace(key, intent);
        // TODO: check disconnection of previous intent
        if (isNotifying)
            notifyListener(new IntentEvent(key, seq, intent, actionId, Type.CHECK_REQ));
    }

    public Intent delIntent(String key, int seq, String actionId, boolean isNotifying) {
        Intent storedIntent = intents.get(key);
        if (storedIntent != null) {
            storedIntent.setState(State.REMOVED);
            if (isNotifying)
                notifyListener(new IntentEvent(key, seq, storedIntent, actionId, Type.CHECK_REQ));
        }

        return storedIntent;
    }

//    public Intent clearIntent(String key, String actionId, boolean isNotifying) {
//        Intent storedIntent = intents.remove(key);
//
//        if (isNotifying)
//            notifyListener(new IntentEvent(key, storedIntent, actionId, Type.CHECK_REQ));
//
//        return storedIntent;
//    }

    public Intent updateIntent(String key, int seq, Type checked, String actionId) {
        Intent storedIntent = intents.get(key);
        if (storedIntent != null)
            notifyListener(new IntentEvent(key, seq, storedIntent, actionId, checked));

        return storedIntent;
    }

    public Intent updateIntent(String key, int seq, State state, Type checked, String actionId) {
        Intent storedIntent = intents.get(key);
        if (storedIntent != null) {
            storedIntent.setState(state);
            notifyListener(new IntentEvent(key, seq, storedIntent, actionId, checked));
        }

        return storedIntent;
    }

    public Intent failTestIntent(String key, int seq, String actionId, String errorMsg) {
        Intent storedIntent = intents.get(key);
        if (storedIntent != null)
            notifyListener(new IntentEvent(key, seq, storedIntent, actionId, Type.TEST_FAILED, errorMsg));

        return storedIntent;
    }

    public void recomputeIntents(TopoGraph topoGraph, Collection<String> changedKeyList) {
        for (Entry<String, Intent> entry : intents.entrySet()) {
            Intent intent = entry.getValue();
            if (State.INSTALLED.equals(intent.getState()) ||
                    State.FAILED.equals(intent.getState())) {
                State newState = TestUtil.getExpectedStateFromIntent(topoGraph, intent);
                State oldState = intent.getState();

                if (!newState.equals(oldState) && changedKeyList != null)
                    changedKeyList.add(entry.getKey());

                intent.setState(newState);
            }
        }
    }

    /**
     * operations without actionId
     */
    public void initIntent(String key, Intent intent) {
        intents.put(key, intent);
        notifyListener(new IntentEvent(key, 0, intent, null, Type.INIT));
    }

    public void addIntent(String key, Intent intent) {
        intents.put(key, intent);
        notifyListener(new IntentEvent(key, 0, intent, null, Type.CHECK_REQ));
    }

    public void modIntent(String key, Intent intent) {
        intents.replace(key, intent);
        notifyListener(new IntentEvent(key, 0, intent, null, Type.CHECK_REQ));
    }

    public boolean isEmpty() {
        return intents.isEmpty();
    }

    /**
     * private methods
     */
    private void notifyListener(IntentEvent event) {
        listeners.forEach(listener -> listener.event(event));
    }

    /**
     * Singleton
     */
    private static class InnerIntentStore {
        private static final IntentStore instance = new IntentStore();
        private static final IntentStore configInstance = new IntentStore();
    }

    public static IntentStore getInstance() {
        return IntentStore.InnerIntentStore.instance;
    }

    public static IntentStore getConfigInstance() {
        return InnerIntentStore.configInstance;
    }
}
