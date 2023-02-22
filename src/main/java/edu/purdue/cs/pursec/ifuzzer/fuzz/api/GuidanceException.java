package edu.purdue.cs.pursec.ifuzzer.fuzz.api;

public class GuidanceException extends RuntimeException {

    public GuidanceException(String msg) {
        super(msg);
    }

    public GuidanceException(Throwable e) {
        super(e);
    }

    public GuidanceException(String msg, Throwable e) {
        super(msg, e);
    }

    public static void wrap(ThrowingRunnable task) {
        try {
            task.run();
        } catch (Exception e) {
            throw new GuidanceException(e);
        }
    }
}
