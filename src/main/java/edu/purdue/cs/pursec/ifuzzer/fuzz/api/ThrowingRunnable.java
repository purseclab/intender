package edu.purdue.cs.pursec.ifuzzer.fuzz.api;

@FunctionalInterface
public interface ThrowingRunnable {
    void run() throws Exception;
}
