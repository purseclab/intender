package edu.purdue.cs.pursec.intenderagent.codec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.onlab.util.Bandwidth;
import org.onosproject.net.DeviceId;
import org.onosproject.net.EncapsulationType;
import org.onosproject.net.Link;
import org.onosproject.net.intent.Constraint;
import org.onosproject.net.intent.constraint.*;

import java.time.Duration;
import java.util.ArrayList;
import java.util.stream.IntStream;

import static org.onlab.util.Tools.nullIsIllegal;
import static org.onosproject.net.intent.constraint.NonDisruptiveConstraint.nonDisruptive;

public final class MyDecodeConstraintCodecHelper {
    private final ObjectNode json;

    /**
     * Constructs a constraint decoder.
     *
     * @param json object node to decode
     */
    public MyDecodeConstraintCodecHelper(ObjectNode json) {
        this.json = json;
    }

    /**
     * Decodes a link type constraint.
     *
     * @return link type constraint object.
     */
    private Constraint decodeLinkTypeConstraint() {
        boolean inclusive = nullIsIllegal(json.get(MyConstraintCodec.INCLUSIVE),
                MyConstraintCodec.INCLUSIVE + MyConstraintCodec.MISSING_MEMBER_MESSAGE).asBoolean();

        JsonNode types = nullIsIllegal(json.get(MyConstraintCodec.TYPES),
                MyConstraintCodec.TYPES + MyConstraintCodec.MISSING_MEMBER_MESSAGE);
        if (types.size() < 1) {
            throw new IllegalArgumentException(
                    "types array in link constraint must have at least one value");
        }

        ArrayList<Link.Type> typesEntries = new ArrayList<>(types.size());
        IntStream.range(0, types.size())
                .forEach(index ->
                        typesEntries.add(Link.Type.valueOf(types.get(index).asText())));

        return new LinkTypeConstraint(inclusive,
                typesEntries.toArray(new Link.Type[types.size()]));
    }

    /**
     * Decodes an annotation constraint.
     *
     * @return annotation constraint object.
     */
    private Constraint decodeAnnotationConstraint() {
        String key = nullIsIllegal(json.get(MyConstraintCodec.KEY),
                MyConstraintCodec.KEY + MyConstraintCodec.MISSING_MEMBER_MESSAGE)
                .asText();
        double threshold = nullIsIllegal(json.get(MyConstraintCodec.THRESHOLD),
                MyConstraintCodec.THRESHOLD + MyConstraintCodec.MISSING_MEMBER_MESSAGE)
                .asDouble();

        return new AnnotationConstraint(key, threshold);
    }

    /**
     * Decodes a latency constraint.
     *
     * @return latency constraint object.
     */
    private Constraint decodeLatencyConstraint() {
        long latencyMillis = nullIsIllegal(json.get(MyConstraintCodec.LATENCY_MILLIS),
                MyConstraintCodec.LATENCY_MILLIS + MyConstraintCodec.MISSING_MEMBER_MESSAGE)
                .asLong();

        return new LatencyConstraint(Duration.ofMillis(latencyMillis));
    }

    /**
     * Decodes an obstacle constraint.
     *
     * @return obstacle constraint object.
     */
    private Constraint decodeObstacleConstraint() {
        JsonNode obstacles = nullIsIllegal(json.get(MyConstraintCodec.OBSTACLES),
                MyConstraintCodec.OBSTACLES + MyConstraintCodec.MISSING_MEMBER_MESSAGE);
        if (obstacles.size() < 1) {
            throw new IllegalArgumentException(
                    "obstacles array in obstacles constraint must have at least one value");
        }

        ArrayList<DeviceId> obstacleEntries = new ArrayList<>(obstacles.size());
        IntStream.range(0, obstacles.size())
                .forEach(index ->
                        obstacleEntries.add(DeviceId.deviceId(obstacles.get(index).asText())));

        return new ObstacleConstraint(
                obstacleEntries.toArray(new DeviceId[obstacles.size()]));
    }

    /**
     * Decodes a waypoint constraint.
     *
     * @return waypoint constraint object.
     */
    private Constraint decodeWaypointConstraint() {
        JsonNode waypoints = nullIsIllegal(json.get(MyConstraintCodec.WAYPOINTS),
                MyConstraintCodec.WAYPOINTS + MyConstraintCodec.MISSING_MEMBER_MESSAGE);
        if (waypoints.size() < 1) {
            throw new IllegalArgumentException(
                    "obstacles array in obstacles constraint must have at least one value");
        }

        ArrayList<DeviceId> waypointEntries = new ArrayList<>(waypoints.size());
        IntStream.range(0, waypoints.size())
                .forEach(index ->
                        waypointEntries.add(DeviceId.deviceId(waypoints.get(index).asText())));

        return new WaypointConstraint(
                waypointEntries.toArray(new DeviceId[waypoints.size()]));
    }

    /**
     * Decodes an asymmetric path constraint.
     *
     * @return asymmetric path constraint object.
     */
    private Constraint decodeAsymmetricPathConstraint() {
        return new AsymmetricPathConstraint();
    }

    /**
     * Decodes a domain constraint.
     *
     * @return domain constraint object.
     */
    private Constraint decodeDomainConstraint() {
        return DomainConstraint.domain();
    }


    /**
     * Decodes a bandwidth constraint.
     *
     * @return bandwidth constraint object.
     */
    private Constraint decodeBandwidthConstraint() {
        double bandwidth = nullIsIllegal(json.get(MyConstraintCodec.BANDWIDTH),
                MyConstraintCodec.BANDWIDTH + MyConstraintCodec.MISSING_MEMBER_MESSAGE)
                .asDouble();

        return new BandwidthConstraint(Bandwidth.bps(bandwidth));
    }

    /**
     * Decodes a non-disruptive reallocation constraint.
     *
     * @return non-disruptive reallocation constraint object.
     */
    private Constraint decodeNonDisruptiveConstraint() {
        return nonDisruptive();
    }

    private Constraint decodeMeteredConstraint() {
        boolean metered = nullIsIllegal(json.get(MyConstraintCodec.METERED),
                MyConstraintCodec.METERED + MyConstraintCodec.MISSING_MEMBER_MESSAGE).asBoolean();
        return new MeteredConstraint(metered);
    }

    /**
     * Decodes a link type constraint.
     *
     * @return link type constraint object.
     */
    private Constraint decodeTierConstraint() {
        boolean inclusive = nullIsIllegal(json.get(MyConstraintCodec.INCLUSIVE),
                MyConstraintCodec.INCLUSIVE + MyConstraintCodec.MISSING_MEMBER_MESSAGE).asBoolean();

        TierConstraint.CostType costType = TierConstraint.CostType.valueOf(nullIsIllegal(
                json.get(MyConstraintCodec.COST_TYPE), MyConstraintCodec.COST_TYPE + MyConstraintCodec.MISSING_MEMBER_MESSAGE
        ).asText());

        JsonNode tiers = nullIsIllegal(json.get(MyConstraintCodec.TIERS),
                MyConstraintCodec.TIERS + MyConstraintCodec.MISSING_MEMBER_MESSAGE);
        if (tiers.size() < 1) {
            throw new IllegalArgumentException(
                    MyConstraintCodec.TIERS + " array in tier constraint must have at least one value");
        }

        ArrayList<Integer> tierEntries = new ArrayList<>(tiers.size());
        IntStream.range(0, tiers.size())
                .forEach(index ->
                        tierEntries.add(new Integer(tiers.get(index).asText())));

        return new TierConstraint(inclusive, costType,
                tierEntries.toArray(new Integer[tiers.size()]));
    }

    private Constraint decodeEncapsulationConstraint() {
        String encapType = nullIsIllegal(json.get(MyConstraintCodec.ENCAPSULATION_TYPE),
                MyConstraintCodec.ENCAPSULATION_TYPE + MyConstraintCodec.MISSING_MEMBER_MESSAGE)
                .asText();

        return new EncapsulationConstraint(EncapsulationType.enumFromString(encapType));
    }

    /**
     * Decodes the given constraint.
     *
     * @return constraint object.
     */
    public Constraint decode() {
        final String type = nullIsIllegal(json.get(MyConstraintCodec.TYPE),
                MyConstraintCodec.TYPE + MyConstraintCodec.MISSING_MEMBER_MESSAGE)
                .asText();

        if (type.equals(BandwidthConstraint.class.getSimpleName())) {
            return decodeBandwidthConstraint();
        } else if (type.equals(LinkTypeConstraint.class.getSimpleName())) {
            return decodeLinkTypeConstraint();
        } else if (type.equals(AnnotationConstraint.class.getSimpleName())) {
            return decodeAnnotationConstraint();
        } else if (type.equals(LatencyConstraint.class.getSimpleName())) {
            return decodeLatencyConstraint();
        } else if (type.equals(ObstacleConstraint.class.getSimpleName())) {
            return decodeObstacleConstraint();
        } else if (type.equals(WaypointConstraint.class.getSimpleName())) {
            return decodeWaypointConstraint();
        } else if (type.equals(AsymmetricPathConstraint.class.getSimpleName())) {
            return decodeAsymmetricPathConstraint();
        } else if (type.equals(DomainConstraint.class.getSimpleName())) {
            return decodeDomainConstraint();
        } else if (type.equals(NonDisruptiveConstraint.class.getSimpleName())) {
            return decodeNonDisruptiveConstraint();
        } else if (type.equals(MeteredConstraint.class.getSimpleName())) {
            return decodeMeteredConstraint();
        } else if (type.equals(TierConstraint.class.getSimpleName())) {
            return decodeTierConstraint();
        } else if (type.equals(EncapsulationConstraint.class.getSimpleName())) {
            return decodeEncapsulationConstraint();
        }

        throw new IllegalArgumentException("Instruction type "
                + type + " is not supported");
    }
}
