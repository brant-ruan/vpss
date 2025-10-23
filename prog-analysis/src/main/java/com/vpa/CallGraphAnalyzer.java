package com.vpa;

import soot.*;
import soot.options.Options;
import soot.jimple.toolkits.callgraph.*;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class CallGraphAnalyzer {
    private static Set<String> packagePrefixes = new HashSet<>();

    public static void run() {
        PackManager.v().runPacks();
    }

    public static void configureSoot(String jarPath, boolean enableSpark, String packagePrefixFilePath) {
        soot.G.reset();

        loadPackagePrefixes(packagePrefixFilePath);

        Options.v().set_src_prec(Options.src_prec_only_class);
        Options.v().set_app(true);
        Options.v().set_prepend_classpath(true);
        Options.v().set_process_dir(Collections.singletonList(jarPath));
        Options.v().set_soot_classpath(Options.v().soot_classpath() + ":" + jarPath);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().setPhaseOption("cg", "all-reachable:true");
        Options.v().set_ignore_resolution_errors(true);
        Options.v().set_ignore_resolving_levels(true);
        Options.v().set_ignore_classpath_errors(true);

        if (!packagePrefixes.isEmpty()) {
            Options.v().set_include(new ArrayList<>(packagePrefixes));
        }

        if (enableSpark) {
            String phase = "cg.spark";
            Options.v().setPhaseOption(phase, "enabled:true");
            Options.v().setPhaseOption(phase, "simulate-natives:true");
            Options.v().setPhaseOption(phase, "on-fly-cg:true");
            Options.v().setPhaseOption(phase, "propagator:worklist");
            // Options.v().setPhaseOption(phase, "rta:true");
        } else {
            String phase = "cg.cha";
            Options.v().setPhaseOption(phase, "enabled:true");
        }

        Scene.v().loadNecessaryClasses();

        List<SootMethod> entryPoints = new ArrayList<>();
        for (SootClass sc : Scene.v().getApplicationClasses()) {
            for (SootMethod sm : sc.getMethods()) {
                boolean matchedPrefix = packagePrefixes.isEmpty();
                for (String prefix : packagePrefixes) {
                    if (sc.getName().startsWith(prefix)) {
                        matchedPrefix = true;
                        break;
                    }
                }
                if (matchedPrefix) {
                    entryPoints.add(sm);
                }
            }
        }
        Scene.v().setEntryPoints(entryPoints);
    }

    public static void saveCallGraphWithVisibilityToJson(CallGraph callGraph, String filePath, String packagePrefixFilePath) {
        // 保证前缀已经加载
        loadPackagePrefixes(packagePrefixFilePath);

        Map<String, JsonObject> nodesMap = new HashMap<>();
        Set<String> uniqueEdges = new HashSet<>();
        JsonObject json = new JsonObject();
        JsonArray edgesArray = new JsonArray();

        for (Edge edge : callGraph) {
            SootMethod srcMethod = edge.getSrc().method();
            if (!srcMethod.getDeclaringClass().isApplicationClass()) continue;

            if (!packagePrefixes.isEmpty()) {
                boolean matchesPrefix = false;
                for (String prefix : packagePrefixes) {
                    if (srcMethod.getDeclaringClass().getName().startsWith(prefix)) {
                        matchesPrefix = true;
                        break;
                    }
                }
                if (!matchesPrefix) continue;
            }

            SootMethod tgtMethod = edge.getTgt().method();

            if (!nodesMap.containsKey(srcMethod.getSignature())) {
                JsonObject node = new JsonObject();
                node.addProperty("signature", srcMethod.getSignature());
                node.addProperty("modifier", getModifier(srcMethod));
                nodesMap.put(srcMethod.getSignature(), node);
            }
            if (!nodesMap.containsKey(tgtMethod.getSignature())) {
                JsonObject node = new JsonObject();
                node.addProperty("signature", tgtMethod.getSignature());
                node.addProperty("modifier", getModifier(tgtMethod));
                nodesMap.put(tgtMethod.getSignature(), node);
            }

            String edgeIdentifier = srcMethod.getSignature() + "->" + tgtMethod.getSignature();
            if (!uniqueEdges.contains(edgeIdentifier)) {
                uniqueEdges.add(edgeIdentifier);
                JsonObject edgeObject = new JsonObject();
                edgeObject.addProperty("src", srcMethod.getSignature());
                edgeObject.addProperty("tgt", tgtMethod.getSignature());
                edgesArray.add(edgeObject);
            }
        }

        JsonArray nodesArray = new JsonArray();
        for (JsonObject node : nodesMap.values()) {
            nodesArray.add(node);
        }
        json.add("nodes", nodesArray);
        json.add("edges", edgesArray);

        try (FileWriter writer = new FileWriter(filePath)) {
            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            gson.toJson(json, writer);
        } catch (IOException e) {
            System.out.println("[-] Failed to save call graph with visibility to JSON: " + e.getMessage());
        }
    }

    private static String getModifier(SootMethod method) {
        if (method.isPublic()) {
            return "public";
        } else if (method.isPrivate()) {
            return "private";
        } else if (method.isProtected()) {
            return "protected";
        } else {
            return "default"; // For package-private methods
        }
    }

    private static void loadPackagePrefixes(String packagePrefixFilePath) {
        if (!packagePrefixes.isEmpty()) return;  // 已加载则跳过

        if (packagePrefixFilePath != null && !packagePrefixFilePath.isEmpty()) {
            try (Scanner scanner = new Scanner(new java.io.File(packagePrefixFilePath))) {
                while (scanner.hasNextLine()) {
                    String line = scanner.nextLine().trim();
                    if (!line.isEmpty()) {
                        packagePrefixes.add(line);
                    }
                }
            } catch (IOException e) {
                System.out.println("[-] Failed to load package prefixes from file: " + e.getMessage());
            }
        }
    }
}
