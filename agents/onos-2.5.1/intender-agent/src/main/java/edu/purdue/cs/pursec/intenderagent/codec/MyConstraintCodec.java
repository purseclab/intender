package edu.purdue.cs.pursec.intenderagent.codec;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onosproject.codec.CodecContext;
import org.onosproject.codec.JsonCodec;
import org.onosproject.net.intent.Constraint;

import static com.google.common.base.Preconditions.checkNotNull;

public class MyConstraintCodec extends JsonCodec<Constraint> {

    protected static final String MISSING_MEMBER_MESSAGE =
            " member is required in Constraint";
    static final String TYPE = "type";
    static final String TYPES = "types";
    static final String INCLUSIVE = "inclusive";
    static final String KEY = "key";
    static final String THRESHOLD = "threshold";
    static final String BANDWIDTH = "bandwidth";
    static final String METERED = "metered";
    static final String LAMBDA = "lambda";
    static final String LATENCY_MILLIS = "latencyMillis";
    static final String OBSTACLES = "obstacles";
    static final String WAYPOINTS = "waypoints";
    static final String TIERS = "tiers";
    static final String COST_TYPE = "costType";
    static final String ENCAPSULATION_TYPE = "encapsulationType";

    @Override
    public ObjectNode encode(Constraint constraint, CodecContext context) {
        checkNotNull(constraint, "Constraint cannot be null");

        final MyEncodeConstraintCodecHelper encodeCodec =
                new MyEncodeConstraintCodecHelper(constraint, context);

        return encodeCodec.encode();
    }

    @Override
    public Constraint decode(ObjectNode json, CodecContext context) {
        checkNotNull(json, "JSON cannot be null");

        final MyDecodeConstraintCodecHelper decodeCodec =
                new MyDecodeConstraintCodecHelper(json);

        return decodeCodec.decode();
    }
}
