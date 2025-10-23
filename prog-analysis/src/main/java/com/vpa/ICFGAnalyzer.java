package com.vpa;

import soot.*;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.jimple.Stmt;
import soot.jimple.IfStmt;
import soot.jimple.LookupSwitchStmt;
import soot.jimple.SwitchStmt;
import soot.jimple.TableSwitchStmt;

import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import java.util.logging.Logger;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

public class ICFGAnalyzer {
    private static final Logger log = LoggerFactory.getLogger();
    private static final Map<String, JsonArray> cachedResults = new HashMap<>();

    public static void analyzeMultipleCGPaths(Set<List<SootMethod>> cgPaths, String outputFilePath) {
        JsonArray combinedResults = new JsonArray();

        for (List<SootMethod> cgPath : cgPaths) {
            JsonArray icfgPaths = new JsonArray();

            for (int i = 0; i < cgPath.size() - 1; i++) {
                SootMethod currentMethod = cgPath.get(i);
                SootMethod nextMethod = cgPath.get(i + 1);

                // Analyze each callsite independently
                JsonArray methodPaths = getControlFlowPaths(currentMethod, nextMethod);
                if (!methodPaths.isEmpty()) {
                    JsonObject methodPathObject = new JsonObject();
                    methodPathObject.addProperty("method", currentMethod.getSignature());
                    methodPathObject.add("paths", methodPaths);
                    icfgPaths.add(methodPathObject);
                }
            }

            // Add the analyzed paths for this CG-level path
            JsonObject cgPathResult = new JsonObject();
            cgPathResult.addProperty("cg_path", cgPath.toString());
            cgPathResult.add("icfg_paths", icfgPaths);
            combinedResults.add(cgPathResult);
        }

        // Save combined results to JSON file
        try (FileWriter writer = new FileWriter(outputFilePath)) {
            new Gson().newBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(combinedResults, writer);
            log.info("ICFG-level paths saved to: " + outputFilePath);
        } catch (IOException e) {
            log.severe("Failed to save combined ICFG-level paths to JSON: " + e.getMessage());
        }
    }

    private static JsonArray getControlFlowPaths(SootMethod method, SootMethod targetCallee) {
        JsonArray paths = new JsonArray();

        if (!method.hasActiveBody()) {
            log.warning("Method has no active body: " + method.getSignature());
            return paths;
        }

        Body body = method.getActiveBody();
        UnitGraph cfg = new ExceptionalUnitGraph(body);

        // Find all callsites invoking the target method
        List<Unit> callSites = new ArrayList<>();
        for (Unit unit : body.getUnits()) {
            if (unit instanceof Stmt) {
                Stmt stmt = (Stmt) unit;
                if (stmt.containsInvokeExpr() && stmt.getInvokeExpr().getMethod().equals(targetCallee)) {
                    callSites.add(unit);
                }
            }
        }

        // For each callsite, find all control flow paths from the entry point to the
        // callsite
        for (Unit callSite : callSites) {
            String callsiteKey = method.getSignature() + ":callsite@" + callSite.toString() + "->"
                    + targetCallee.getSignature();
            JsonArray cachedPath = cachedResults.get(callsiteKey);

            if (cachedPath != null) {
                log.fine("Reusing cached result for: " + callsiteKey);
                paths.addAll(cachedPath);
                continue;
            }

            List<List<Unit>> cfPaths = findPathsInCFG(cfg, cfg.getHeads(), callSite);
            JsonArray callsitePaths = new JsonArray();

            for (List<Unit> path : cfPaths) {
                JsonObject pathObject = new JsonObject();
                JsonArray jsonPath = new JsonArray();
                JsonArray constraints = generatePathConstraints(path);

                for (Unit unit : path) {
                    jsonPath.add(unit.toString());
                }

                JsonObject dataAnalysisResult = getDataFlowAnalysis(method, path);
                // analyzeIntermediateMethodCallsWithCallTrace(path, callSite, pathObject, new HashSet<>(), new LinkedList<>());
                
                pathObject.add("path", jsonPath);
                pathObject.add("constraints", constraints);
                pathObject.add("data_dependency_graph", dataAnalysisResult);
                
                callsitePaths.add(pathObject);
            }

            cachedResults.put(callsiteKey, callsitePaths);
            paths.addAll(callsitePaths);
        }

        return paths;
    }

    private static JsonArray generatePathConstraints(List<Unit> path) {
        JsonArray constraints = new JsonArray();
        List<String> effectiveConstraints = new ArrayList<>();

        for (Unit unit : path) {
            if (unit instanceof IfStmt || unit instanceof SwitchStmt) {
                processControlDependency(unit, path, effectiveConstraints);
            }
        }

        for (String constraint : effectiveConstraints) {
            constraints.add(constraint);
        }
        return constraints;
    }

    private static void processControlDependency(Unit unit, List<Unit> path, List<String> effectiveConstraints) {
        if (unit instanceof IfStmt) {
            IfStmt ifStmt = (IfStmt) unit;
            boolean isTrueBranch = path.contains(ifStmt.getTarget());
            String condition = ifStmt.getCondition().toString();
            effectiveConstraints.add(isTrueBranch ? condition : "!(" + condition + ")");
        } else if (unit instanceof LookupSwitchStmt) {
            LookupSwitchStmt switchStmt = (LookupSwitchStmt) unit;
            for (Unit target : switchStmt.getTargets()) {
                if (path.contains(target)) {
                    int index = switchStmt.getTargets().indexOf(target);
                    String condition = index < switchStmt.getLookupValues().size()
                            ? switchStmt.getKey().toString() + " == " + switchStmt.getLookupValues().get(index)
                            : "default";
                    effectiveConstraints.add(condition);
                }
            }
        } else if (unit instanceof TableSwitchStmt) {
            TableSwitchStmt switchStmt = (TableSwitchStmt) unit;
            for (Unit target : switchStmt.getTargets()) {
                if (path.contains(target)) {
                    int index = switchStmt.getTargets().indexOf(target);
                    int low = switchStmt.getLowIndex();
                    String condition = (index + low <= switchStmt.getHighIndex())
                            ? switchStmt.getKey().toString() + " == " + (low + index)
                            : "default";
                    effectiveConstraints.add(condition);
                }
            }
        }
    }

    private static List<List<Unit>> findPathsInCFG(UnitGraph cfg, List<Unit> starts, Unit target) {
        List<List<Unit>> resultPaths = new ArrayList<>();
        LinkedList<Unit> currentPath = new LinkedList<>();
        Set<Unit> visited = new HashSet<>();

        for (Unit start : starts) {
            dfsCFG(cfg, start, target, currentPath, visited, resultPaths);
        }

        return resultPaths;
    }

    private static void dfsCFG(UnitGraph cfg, Unit current, Unit target, LinkedList<Unit> currentPath,
            Set<Unit> visited, List<List<Unit>> resultPaths) {
        if (visited.contains(current)) {
            return;
        }

        visited.add(current);
        currentPath.add(current);

        if (current.equals(target)) {
            resultPaths.add(new ArrayList<>(currentPath));
        } else {
            for (Unit successor : cfg.getSuccsOf(current)) {
                dfsCFG(cfg, successor, target, currentPath, visited, resultPaths);
            }
        }

        currentPath.removeLast();
        visited.remove(current);
    }
    
    private static JsonObject getDataFlowAnalysis(SootMethod method, List<Unit> path) {
        JsonObject analysisResult = new JsonObject();
        JsonArray ddgEdges = new JsonArray();
        Map<Local, Set<Local>> dependencies = new HashMap<>();

        for (Unit unit : path) {
            List<ValueBox> defBoxes = unit.getDefBoxes();
            List<ValueBox> useBoxes = unit.getUseBoxes();

            Set<Local> definedLocals = new HashSet<>();
            for (ValueBox defBox : defBoxes) {
                if (defBox.getValue() instanceof Local) {
                    definedLocals.add((Local) defBox.getValue());
                }
            }

            for (ValueBox useBox : useBoxes) {
                if (useBox.getValue() instanceof Local) {
                    Local usedLocal = (Local) useBox.getValue();
                    dependencies.putIfAbsent(usedLocal, new HashSet<>());
                    dependencies.get(usedLocal).addAll(definedLocals);
                }
            }
        }

        for (Map.Entry<Local, Set<Local>> entry : dependencies.entrySet()) {
            for (Local dependency : entry.getValue()) {
                JsonObject edge = new JsonObject();
                edge.addProperty("from", dependency.getName());
                edge.addProperty("to", entry.getKey().getName());
                ddgEdges.add(edge);
            }
        }

        analysisResult.add("edges", ddgEdges);
        return analysisResult;
    }
}
