package edu.purdue.cs.pursec.ifuzzer.api;

import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoGraphListener;

public interface MQReceiver {
    public void start();
    public void stop();
    public void addListener(TopoGraphListener listener);
}
