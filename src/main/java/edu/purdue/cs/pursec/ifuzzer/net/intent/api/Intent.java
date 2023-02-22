package edu.purdue.cs.pursec.ifuzzer.net.intent.api;


public interface Intent {
    enum State {
        REQ ("REQ"),
        INSTALLED ("INSTALLED"),
        FAILED ("FAILED"),
        CORRUPT ("CORRUPT"),
        WITHDRAWN ("WITHDRAWN"),
        WITHDRAWING ("WITHDRAWING"),
        EXCEPTIONAL ("EXCEPTIONAL"),      // used only by IntentStateCoverage
        REMOVED ("REMOVED");

        private final String state;

        private State(String state) {
            this.state = state;
        }

        public boolean equals(String state) {
            return this.state.equals(state);
        }

        public static State onosOf (String state) {
            if (state.equals("INSTALLING"))
                return REQ;
            else if (state.equals("INSTALLED"))
                return INSTALLED;
            else if (state.equals("FAILED"))
                return FAILED;
            else if (state.equals("WITHDRAWN"))
                return WITHDRAWN;
            else if (state.equals("CORRUPT"))
                return CORRUPT;
            else if (state.equals("REMOVED"))
                return REMOVED;
            else if (state.equals("WITHDRAWING"))
                return WITHDRAWING;
            return null;
        }

        // Used for IntentStateCoverage
        public byte toByteCode() {
            if (INSTALLED.equals(this))
                return 1;
            if (FAILED.equals(this))
                return 2;
            if (WITHDRAWN.equals(this))
                return 3;
            if (REMOVED.equals(this))
                return 4;
            // Error case
            return 5;
        }

        public static State fromByteCode(byte code) {
            switch (code) {
                case 1:
                    return INSTALLED;
                case 2:
                    return FAILED;
                case 3:
                    return WITHDRAWN;
                case 4:
                    return REMOVED;
                case 5:
                    return EXCEPTIONAL;
                default:
                    return null;
            }
        }

        public static String shortStateFromByteCode(byte code) {
            switch (code) {
                case 1:
                    return "I";
                case 2:
                    return "F";
                case 3:
                    return "W";
                case 4:
                    return "X";
                case 5:
                    return "E";
                default:
                    return String.valueOf(code);
            }
        }
    }

    String toString();
    String getKey();
    void setKey(String key);
    String getAppId();
    State getState();
    void setState(State state);
    int getPriority();
    void setPriority(int priority);
    boolean isValid();
    boolean equalsConfig(Intent intent);
    boolean doNotDPTest();
}
