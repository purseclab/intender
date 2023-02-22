package edu.purdue.cs.pursec.ifuzzer.net.intent.api;

public class IntentType {
    private final String type;

    public static final IntentType HostToHostIntent = new IntentType("HostToHostIntent");
    public static final IntentType PointToPointIntent = new IntentType("PointToPointIntent");
    public static final IntentType SinglePointToMultiPointIntent = new IntentType("SinglePointToMultiPointIntent");
    public static final IntentType MultiPointToSinglePointIntent = new IntentType("MultiPointToSinglePointIntent");

    private IntentType(String type) {
        this.type = type;
    }

    public String toString() {
        return type;
    }
}
