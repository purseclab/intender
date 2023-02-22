package edu.purdue.cs.pursec.ifuzzer.comm.api;

public interface IntentInterface {
    IntentInterfaceResponse getIntent(String key);
    IntentInterfaceResponse addIntent(String intent);
    IntentInterfaceResponse modIntent(String key, String appId, String intent);
    IntentInterfaceResponse deleteIntent(String key);
    IntentInterfaceResponse withdrawIntent(String key, String appId);
    IntentInterfaceResponse purgeIntent(String key, String appId);
}
