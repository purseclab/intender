package edu.purdue.cs.pursec.ifuzzer.net.flow.impl;

import edu.purdue.cs.pursec.ifuzzer.net.flow.api.Rule;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.VerifyPortId;
import edu.purdue.cs.pursec.ifuzzer.net.flow.api.VerifyRuleId;
import jdd.bdd.BDD;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/* Code from PAZZ */
public class PathWrapper {

    public BDD bdd = null;
    ArrayList<ArrayList<VerifyRuleId>> rules = new ArrayList<>();
    ArrayList<ArrayList<Integer>> predicates = new ArrayList<ArrayList<Integer>>();
    ArrayList<ArrayList<VerifyPortId>> ports = new ArrayList<>();
    Map<Integer, Rule> networkRules = new LinkedHashMap<Integer, Rule>();


    public PathWrapper(){

    }
    public PathWrapper(PathWrapper wrapper){
        bdd = wrapper.bdd;
        rules.addAll(wrapper.getPaths());
        predicates.addAll(wrapper.getPredicates());
        ports.addAll(wrapper.getPorts());

        networkRules.putAll(wrapper.getNetworkRules());
        //System.out.println("PathWrapper constructor adding paths"+ this.getPaths().toString());

    }

    /**
     * @return the networkRules
     */
    public Map<Integer, Rule> getNetworkRules() {
        return networkRules;
    }
    /**
     * @return the ports
     */
    public ArrayList<ArrayList<VerifyPortId>> getPorts() {
        return ports;
    }

    /**
     * @param ports the ports to set
     */
    public void addPorts(ArrayList<ArrayList<VerifyPortId>> ports) {
        this.ports.addAll(ports);
    }



    /**
     * @param networkRules the networkRules to set
     */
    public void setNetworkRules(Map<Integer, Rule> networkRules) {
        this.networkRules = networkRules;
    }
    /**
     * @return the paths
     */
    public ArrayList<ArrayList<VerifyRuleId>> getPaths() {
        return rules;
    }
    /**
     * @param paths the paths to set
     */
    public void addPaths(ArrayList<ArrayList<VerifyRuleId>> paths) {
        this.rules.addAll(paths);
    }
    /**
     * @return the predicates
     */
    public ArrayList<ArrayList<Integer>> getPredicates() {
        return predicates;
    }
    /**
     * @param predicates the predicates to set
     */
    public void addPredicates(ArrayList<ArrayList<Integer>> predicates) {
        this.predicates.addAll(predicates);
    }


    public void printStats(){
        //System.out.println("Total Number of paths were "+rules.size());
    }

    public ArrayList<String> pathStrings(){
        ArrayList<String> pathString = new ArrayList<String>();
        for(ArrayList<VerifyRuleId> path: rules){
            pathString.add(path.toString());
        }
        return pathString;
    }

    public ArrayList<String> portStrings(){
        ArrayList<String> portString = new ArrayList<String>();
        for(ArrayList<VerifyPortId> port: ports){
            portString.add(port.toString());
        }
        return portString;
    }

    public ArrayList<String> pathAndPortStrings(){
        ArrayList<String> portPathString = new ArrayList<String>();
        portPathString.add("rules:" );
        portPathString.addAll(pathStrings());
        portPathString.add("ports:");
        portPathString.addAll(portStrings());
        return portPathString;
    }

    public void printPaths(){
        Iterator<ArrayList<VerifyRuleId>> pathListIterator = rules.iterator();
        Iterator<ArrayList<Integer>> predicateListIterator = predicates.iterator();
        while(pathListIterator.hasNext() && predicateListIterator.hasNext()){
            ArrayList<VerifyRuleId> rules = pathListIterator.next();
            ArrayList<Integer> predicates = predicateListIterator.next();
            Iterator<VerifyRuleId> ruleIterator = rules.iterator();
            Iterator<Integer> predicateIterator = predicates.iterator();
            //System.out.println("Path Number: "+rules.indexOf(rules));
            Rule rule = null;
            int predicate = 0 ;
            while(ruleIterator.hasNext() && predicateIterator.hasNext()){
                rule = networkRules.get(ruleIterator.next());
                predicate = predicateIterator.next();
                //System.out.print("Rule ID:"+rule.rule_id+" Predicate: "+predicate+"--->");
            }
            //System.out.println();
        }

    }

}
