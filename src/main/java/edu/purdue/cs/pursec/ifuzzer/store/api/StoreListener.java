package edu.purdue.cs.pursec.ifuzzer.store.api;

public interface StoreListener<E extends StoreEvent> {
    void event(E e);
}
