package com.vpa;

import pascal.taie.analysis.graph.callgraph.CallGraph;
import pascal.taie.analysis.pta.core.cs.element.CSCallSite;
import pascal.taie.analysis.pta.core.cs.element.CSMethod;
import pascal.taie.analysis.pta.core.heap.HeapModel;
import pascal.taie.analysis.pta.core.solver.DeclaredParamProvider;
import pascal.taie.analysis.pta.core.solver.EntryPoint;
import pascal.taie.analysis.pta.core.solver.Solver;
import pascal.taie.analysis.pta.plugin.Plugin;
import pascal.taie.language.classes.ClassHierarchy;
import pascal.taie.language.classes.JClass;
import pascal.taie.language.classes.JMethod;
import pascal.taie.language.type.TypeSystem;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.io.FileWriter;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class CustomEntryPointPlugin implements Plugin {

    private Solver solver;

    private ClassHierarchy hierarchy;

    private TypeSystem typeSystem;

    private HeapModel heapModel;

    @Override
    public void setSolver(Solver solver) {
        this.solver = solver;
        this.hierarchy = solver.getHierarchy();
        this.typeSystem = solver.getTypeSystem();
        this.heapModel = solver.getHeapModel();
    }

    @Override
    public void onStart() {
        String classListPath = System.getProperty("plugin.classlist.file");
        if (classListPath == null) {
            System.err.println("[Plugin] System property 'plugin.classlist.file' not set.");
            return;
        }
        String outputPath = System.getProperty("plugin.output.cg.file");
        if (outputPath == null) {
            System.err.println("[Plugin] System property 'plugin.output.cg.file' not set.");
            return;
        }

        System.out.println("[Plugin] Reading class list from: " + classListPath);
        List<String> targetClasses;

        try {
            targetClasses = Files.readAllLines(Paths.get(classListPath));
        } catch (IOException e) {
            System.err.println("[Plugin] Failed to read class list file: " + e.getMessage());
            return;
        }

        for (String className : targetClasses) {
            className = className.trim();
            if (className.isEmpty()) continue;

            JClass clz = hierarchy.getClass(className);
            if (clz == null) {
                System.err.println("[Plugin] Class not found: " + className);
                continue;
            }

            for (JMethod method : clz.getDeclaredMethods()) {
                if ((method.isPublic() || method.isProtected()) && !method.isAbstract()) {
                    EntryPoint ep = new EntryPoint(method, new DeclaredParamProvider(method, heapModel, 1));
                    solver.addEntryPoint(ep);
                }
            }
        }
    }

    @Override
    public void onFinish() {
        // Save the call graph to JSON
        CallGraph<CSCallSite, CSMethod> callGraph = solver.getCallGraph();
        String outputPath = System.getProperty("plugin.output.cg.file");
        if (outputPath == null) {
            System.err.println("[Plugin] System property 'plugin.output.cg.file' not set.");
            return;
        }

        Map<String, JsonObject> nodesMap = new HashMap<>();
        Set<String> uniqueEdges = new HashSet<>();
        JsonObject json = new JsonObject();
        JsonArray edgesArray = new JsonArray();

        callGraph.edges().forEach(edge -> {
            JMethod caller = edge.getCallSite().getContainer().getMethod();
            JMethod callee = edge.getCallee().getMethod();

            if (!nodesMap.containsKey(caller.getSignature())) {
                JsonObject node = new JsonObject();
                node.addProperty("signature", caller.getSignature());
                node.addProperty("modifier", getModifier(caller));
                nodesMap.put(caller.getSignature(), node);
            }
            if (!nodesMap.containsKey(callee.getSignature())) {
                JsonObject node = new JsonObject();
                node.addProperty("signature", callee.getSignature());
                node.addProperty("modifier", getModifier(callee));
                nodesMap.put(callee.getSignature(), node);
            }

            String edgeIdentifier = caller.getSignature() + "->" + callee.getSignature();
            if (!uniqueEdges.contains(edgeIdentifier)) {
                uniqueEdges.add(edgeIdentifier);
                JsonObject edgeObject = new JsonObject();
                edgeObject.addProperty("src", caller.getSignature());
                edgeObject.addProperty("tgt", callee.getSignature());
                edgesArray.add(edgeObject);
            }
        });

        JsonArray nodesArray = new JsonArray();
        for (JsonObject node : nodesMap.values()) {
            nodesArray.add(node);
        }
        json.add("nodes", nodesArray);
        json.add("edges", edgesArray);

        try (FileWriter writer = new FileWriter(outputPath)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            gson.toJson(json, writer);
        } catch (IOException e) {
            System.err.println("[Plugin] Failed to save call graph to JSON: " + e.getMessage());
        }
    }

    private String getModifier(JMethod method) {
        if (method.isPublic()) {
            return "public";
        } else if (method.isProtected()) {
            return "protected";
        } else if (method.isPrivate()) {
            return "private";
        } else {
            return "default";
        }
    }
}