package edu.purdue.cs.pursec.ifuzzer.net.flow.api;

import java.util.ArrayList;
import java.util.List;

public class VerifyRuleId {
    long dpid;
    int localRuleId;

    public VerifyRuleId(long dpid, int localRuleId) {
        this.dpid = dpid;
        this.localRuleId = localRuleId;
    }

    @Override
    public boolean equals(Object obj) {
        if (!(obj instanceof VerifyRuleId))
            return false;

        VerifyRuleId that = (VerifyRuleId)obj;

        if (this.dpid != that.dpid)
            return false;

        if (this.localRuleId != that.localRuleId)
            return false;

        return true;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        return sb.append(dpid).append(',').append(' ').append(localRuleId).toString();
    }

    public String dump() {
        return "VerifyRuleId{" +
                "dpid=" + dpid +
                ", localRuleId=" + localRuleId +
                '}';
    }
}
