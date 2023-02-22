package edu.purdue.cs.pursec.ifuzzer.net.flow.api;

public class VerifyPortId {
    long dpid;
    int localPortId;

    public VerifyPortId(long dpid, int localPortId) {
        this.dpid = dpid;
        this.localPortId = localPortId;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof VerifyPortId))
            return false;

        VerifyPortId that = (VerifyPortId)obj;

        if (this.dpid != that.dpid)
            return false;

        if (this.localPortId != that.localPortId)
            return false;

        return true;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        return sb.append(dpid).append(',').append(' ').append(localPortId).toString();
    }

    public String dump() {
        return "VerifyPortId{" +
                "dpid=" + dpid +
                ", localPortId=" + localPortId +
                '}';
    }
}
