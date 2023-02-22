package edu.purdue.cs.pursec.ifuzzer.net.topo.impl;

import edu.purdue.cs.pursec.ifuzzer.net.topo.api.*;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoElem.State;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoGraphEvent.Type;
import edu.purdue.cs.pursec.ifuzzer.util.MQUtil;
import org.jgrapht.alg.shortestpath.DijkstraShortestPath;
import org.jgrapht.graph.DirectedMultigraph;

import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.stream.Collectors;

public class TopoGraph {
    private DirectedMultigraph<TopoNode, TopoEdge> graph;
    private final Set<TopoGraphListener> listeners;
    private final Map<String, Set<TopoEdge>> tempEdges;

    private TopoGraph() {
        this.graph = new DirectedMultigraph<TopoNode, TopoEdge>(TopoEdge.class);
        listeners = new CopyOnWriteArraySet<TopoGraphListener>();
        tempEdges = new HashMap<>();
    }

    public void addListener(TopoGraphListener listener) {
        listeners.add(listener);
    }

    public Set<TopoElem> getAllElem() {
        Set<TopoElem> set = new HashSet<>();
        set.addAll(getAllNodes());
        set.addAll(getAllEdges());
        return set;
    }

    public boolean pathExists(TopoNode src, TopoNode dst) {
        return pathExists(src, dst, false);
    }

    public boolean pathExists(TopoNode src, TopoNode dst, boolean isBothWay) {
        if (src == null || State.INACTIVE.equals(src.getState()))
            return false;

        if (dst == null || State.INACTIVE.equals(dst.getState()))
            return false;

        // TODO: can optimize performance by managing activeGraph
        DirectedMultigraph<TopoNode, TopoEdge> activeGraph = new DirectedMultigraph<>(TopoEdge.class);
        graph.vertexSet().stream()
                .filter(k -> State.ACTIVE.equals(k.getState()))
                .forEach(activeGraph::addVertex);

        graph.edgeSet().stream()
                .filter(k -> State.ACTIVE.equals(k.getState()))
                .map(k -> {
                    TopoNode srcNode = getNode(k.getSrcId());
                    TopoNode dstNode = getNode(k.getDstId());
                    if ((srcNode == null) || !(State.ACTIVE.equals(srcNode.getState())))
                        return false;

                    if ((dstNode == null) || !(State.ACTIVE.equals(dstNode.getState())))
                        return false;

                    return activeGraph.addEdge(srcNode, dstNode, k);
                }).collect(Collectors.toSet());

        if (isBothWay) {
            if (DijkstraShortestPath.findPathBetween(activeGraph, dst, src) == null)
                return false;
        }

        return (DijkstraShortestPath.findPathBetween(activeGraph, src, dst) != null);
    }

    /**
     * node methods
     */
    public synchronized void addNode(TopoNode node) {
        if (graph.addVertex(node)) {
            addEdge(node);
            notifyListener(new TopoGraphEvent(node, Type.PUT));
        }
    }

    public TopoNode getNode(String id) {
        if (id == null)
            return null;

        for (TopoNode node : graph.vertexSet()) {
            if (node.getId().equals(id))
                return node;
        }

        return null;
    }

    public Set<TopoNode> getAllNodes() {
        return graph.vertexSet();
    }

    public synchronized Set<TopoDevice> getAllDevices() {
        Set<TopoDevice> devices = new HashSet<>();
        for (TopoNode node : graph.vertexSet()) {
            if (node instanceof TopoDevice)
                devices.add((TopoDevice) node);
        }

        return devices;
    }

    public synchronized Set<TopoHost> getAllHosts(boolean onlyActive) {
        return graph.vertexSet().stream()
                .filter(k -> k instanceof TopoHost)
                .map(k -> (TopoHost) k)
                .filter(k -> !onlyActive || State.ACTIVE.equals(k.getState()))
                .collect(Collectors.toSet());
    }

    public boolean updateStateNode(State state, TopoNode node) {
        if (state == null || node == null)
            return false;

        State oldState = node.getState();
        if (!oldState.equals(state)) {
            node.setState(state);
            notifyListener(new TopoGraphEvent(node, MQUtil.topoStateToEventType(state)));
        }
        return true;
    }

    public synchronized void removeHost(TopoHost host) {
        if (graph.removeVertex(host)) {
            notifyListener(new TopoGraphEvent(host, Type.REMOVE));
        }
    }

    /**
     * edge methods
     */
    private void addEdge(TopoNode node) {
        Set<TopoEdge> tempSet = tempEdges.remove(node.getId());
        if (tempSet != null) {
            tempSet.forEach(this::addEdge);
        }
    }

    public synchronized void addEdge(TopoEdge edge) {
        if (edge.getSrcId().equals(edge.getDstId()))
            return;

        TopoNode src = getNode(edge.getSrcId());
        TopoNode dst = getNode(edge.getDstId());

        if (src == null) {
            Set<TopoEdge> tempSet = tempEdges.computeIfAbsent(edge.getSrcId(), k -> new HashSet<>());
            tempSet.add(edge);
        } else if (dst == null) {
            Set<TopoEdge> tempSet = tempEdges.computeIfAbsent(edge.getDstId(), k -> new HashSet<>());
            tempSet.add(edge);
        } else {
            // multi-link
            if (graph.containsEdge(src, dst)) {
                boolean found = false;
                for (TopoEdge storedEdge : graph.getAllEdges(src, dst)) {
                    if (storedEdge.getId().equals(edge.getId())) {
                        storedEdge.setState(edge.getState());
                        notifyListener(new TopoGraphEvent(storedEdge, Type.PUT));
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    if (graph.addEdge(src, dst, edge))
                        notifyListener(new TopoGraphEvent(edge, Type.PUT));
                }
            } else if (graph.addEdge(src, dst, edge)) {
                notifyListener(new TopoGraphEvent(edge, Type.PUT));
            }
        }
    }

    public TopoEdge getEdge(String id) {
        if (id == null)
            return null;

        for (TopoEdge edge : graph.edgeSet()) {
            if (edge.getId().equals(id))
                return edge;
        }

        for (Set<TopoEdge> set : tempEdges.values()) {
            for (TopoEdge edge : set) {
                if (edge.getId().equals(id))
                    return edge;
            }
        }

        return null;
    }

    public TopoEdge getEdgeFromSrc(String srcId, String srcPort) {
        if (srcId == null)
            srcId = "";

        if (srcPort == null)
            srcPort = "";

        String prefixId = srcId + '/' + srcPort;

        for (TopoEdge edge : graph.edgeSet()) {
            if (State.ACTIVE.equals(edge.getState()) && edge.getId().startsWith(prefixId))
                return edge;
        }

        // XXX: Does it need?
        for (Set<TopoEdge> set : tempEdges.values()) {
            for (TopoEdge edge : set) {
                if (edge.getId().startsWith(prefixId))
                    return edge;
            }
        }

        return null;
    }

    public TopoEdge getEdgeFromDst(String dstId, String dstPort) {
        if (dstId == null)
            dstId = "";

        if (dstPort == null)
            dstPort = "";

        String suffixId = dstId + '/' + dstPort;

        for (TopoEdge edge : graph.edgeSet()) {
            if (State.ACTIVE.equals(edge.getState()) && edge.getId().endsWith(suffixId))
                return edge;
        }

        // XXX: Does it need?
        for (Set<TopoEdge> set : tempEdges.values()) {
            for (TopoEdge edge : set) {
                if (edge.getId().endsWith(suffixId))
                    return edge;
            }
        }

        return null;
    }

    public TopoEdge getEdgeFromNodes(String srcId, String dstId) {
        if (srcId == null || dstId == null)
            return null;

        for (TopoEdge edge : graph.edgeSet()) {
            String[] edgeId = edge.getId().split(" ");
            assert(edgeId.length == 2);

            if (!State.ACTIVE.equals(edge.getState()))
                continue;

            if (edgeId[0].startsWith(srcId) && edgeId[1].startsWith(dstId))
                return edge;
        }

        // XXX: Does it need?
        for (Set<TopoEdge> set : tempEdges.values()) {
            for (TopoEdge edge : set) {
                String[] edgeId = edge.getId().split(" ");
                assert(edgeId.length == 2);

                if (edgeId[0].startsWith(srcId) && edgeId[1].startsWith(dstId))
                    return edge;
            }
        }

        return null;
    }

    public boolean updateStateEdge(State state, String id) {
        TopoEdge edge = getEdge(id);

        return updateStateEdge(state, edge);
    }

    public boolean updateStateEdge(State state, TopoEdge edge) {
        if (state == null || edge == null)
            return false;

        State oldState = edge.getState();
        if (!state.equals(oldState)) {
            edge.setState(state);
            notifyListener(new TopoGraphEvent(edge, MQUtil.topoStateToEventType(state)));
        }
        return true;
    }

    public Set<TopoEdge> getAllEdges() {
        return graph.edgeSet();
    }

    public Set<TopoLink> getAllLinks() {
        Set<TopoLink> links = new HashSet<>();
        for (TopoEdge edge : graph.edgeSet()) {
            if (edge instanceof TopoLink)
                links.add((TopoLink) edge);
        }

        return links;
    }

    public Set<TopoEdge> getAllTempEdges() {
        Set<TopoEdge> set = new HashSet<>();
        tempEdges.values().forEach(set::addAll);
        return set;
    }

    public synchronized void removeHostEdge(TopoHostEdge edge) {
        if (graph.removeEdge(edge)) {
            notifyListener(new TopoGraphEvent(edge, Type.REMOVE));
        }
    }

    /**
     * Topology-Operation Methods
     * ASSUMPTION: There is one edge between two nodes.
     */

    public void add(TopoElem elem) {
        if (elem instanceof TopoNode) {
            TopoNode targetNode = this.getNode(elem.getId());
            if (targetNode == null)
                this.addNode((TopoNode) elem);
            else
                this.updateStateNode(State.ACTIVE, targetNode);

        } else if (elem instanceof TopoEdge) {
            TopoEdge topoEdge = (TopoEdge) elem;
            TopoEdge targetEdge = this.getEdgeFromNodes(topoEdge.getSrcId(), topoEdge.getDstId());

            if (targetEdge == null)
                this.addEdge((TopoEdge) elem);
            else
                this.updateStateEdge(State.ACTIVE, targetEdge);
        }
    }

    public void remove(TopoElem elem) {
        if (elem instanceof TopoNode) {
            TopoNode targetNode = this.getNode(elem.getId());

            if (targetNode instanceof TopoHost)
                this.removeHost((TopoHost)targetNode);
            else
                this.updateStateNode(State.INACTIVE, targetNode);

        } else if (elem instanceof TopoEdge) {
            TopoEdge topoEdge = (TopoEdge) elem;
            TopoEdge targetEdge = this.getEdgeFromNodes(topoEdge.getSrcId(), topoEdge.getDstId());

            if (targetEdge instanceof TopoHostEdge)
                this.removeHostEdge((TopoHostEdge)targetEdge);
            else
                this.updateStateEdge(State.INACTIVE, targetEdge);

        }
    }

    public void applyTopoOperation(TopoOperation topoOperation) {
        TopoElem topoElem = topoOperation.getElem();
        if (topoOperation.getType().equals(TopoOperation.Type.ADD)) {
            // ADD
            topoElem.setState(State.ACTIVE);    // set state as active
            this.add(topoElem);

            // Add additional elements
            if (topoElem instanceof TopoHost) {
                TopoHost topoHost = (TopoHost) topoElem;
                this.add(new TopoHostEdge(topoOperation.getDpid(), topoHost.getId(),
                        topoOperation.getPort() == null ? "0" : topoOperation.getPort(), null));
                this.add(new TopoHostEdge(topoHost.getId(), topoOperation.getDpid(),
                        null, topoOperation.getPort() == null ? "0" : topoOperation.getPort()));
            } else if (topoElem instanceof TopoLink) {
                // link operation should be bidirectional
                TopoLink invertLink = TopoLink.invert((TopoLink)topoElem);
                invertLink.setState(State.ACTIVE);
                this.add(invertLink);
            }

        } else {
            // DELETE
            this.remove(topoElem);

            // Delete additional elements
            if (topoElem instanceof TopoHost) {
                TopoHost topoHost = (TopoHost) topoElem;
                for (TopoEdge topoEdge : getAllEdges()) {
                    if (!(topoEdge instanceof TopoHostEdge))
                        continue;

                    if (topoEdge.getSrcId().equals(topoHost.getId()) ||
                            topoEdge.getDstId().equals(topoHost.getId()))
                        this.removeHostEdge((TopoHostEdge)topoEdge);
                }
            } else if (topoElem instanceof TopoLink) {
                // link operation should be bidirectional
                TopoLink invertLink = TopoLink.invert((TopoLink)topoElem);
                this.remove(invertLink);
            }
        }
    }

    /**
     * private methods
     */
    private void notifyListener(TopoGraphEvent event) {
        listeners.forEach(listener -> listener.event(event));
    }

    /**
     * Singleton
     */
    private static class InnerTopoGraph {
        private static final TopoGraph operinstance = new TopoGraph();
        private static final TopoGraph configinstance = new TopoGraph();
    }

    public static TopoGraph getOperationalTopology() {
        return InnerTopoGraph.operinstance;
    }

    public static TopoGraph getConfigTopology() {
        return InnerTopoGraph.configinstance;
    }
}
