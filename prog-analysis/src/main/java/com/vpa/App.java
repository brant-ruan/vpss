package com.vpa;

import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import org.apache.commons.cli.*;

public class App {
    public void generateCallGraph(String jarPath, String outPath, String cgType, String packagePrefix) {
        boolean enableSpark = false;
        if (cgType.equals("spark")) {
            enableSpark = true;
        }
        CallGraphAnalyzer.configureSoot(jarPath, enableSpark, packagePrefix);
        CallGraphAnalyzer.run();
        CallGraph cg = Scene.v().getCallGraph();
        CallGraphAnalyzer.saveCallGraphWithVisibilityToJson(cg, outPath, packagePrefix);
    }

    public static void main(String[] args) {
        Options options = new Options();
        options.addOption("t", "task", true, "Task to perform (gen-cg, check-call or check-reflect)");
        options.addOption("j", "jar-path", true, "Path to the JAR file");
        options.addOption("o", "out", true, "Output file path (used for gen-cg)");
        options.addOption("c", "cg-type", true, "Call graph type (cha or spark) (used for gen-cg)");
        options.addOption("p", "package-prefix", true, "Package prefix file to filter the call graph");
        options.addOption("m", "method-list", true, "Path to the critical method list");
        options.addOption("h", "help", false, "Show help");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        try {
            CommandLine cmd = parser.parse(options, args);

            if (cmd.hasOption("h")) {
                formatter.printHelp("java -jar prog-analysis.jar", options);
                return;
            }

            String task = cmd.getOptionValue("task");
            if (task == null) {
                System.err.println("--task is required");
                System.exit(1);
            }

            switch (task) {
                case "gen-cg":
                    String jarPath = cmd.getOptionValue("jar-path");
                    String outPath = cmd.getOptionValue("out");
                    String cgType = cmd.getOptionValue("cg-type", "spark");
                    String packagePrefix = cmd.getOptionValue("package-prefix", "");
                    if (jarPath == null || outPath == null) {
                        System.err.println("--jar-path and --out are required for gen-cg");
                        System.exit(1);
                    }
                    if (!cgType.equals("cha") && !cgType.equals("spark")) {
                        System.err.println("[-] --cg-type must be either 'cha' or 'spark'");
                        System.exit(1);
                    }
                    new App().generateCallGraph(jarPath, outPath, cgType, packagePrefix);
                    break;
                case "check-call":
                    jarPath = cmd.getOptionValue("jar-path");
                    String criticalMethodsFile = cmd.getOptionValue("method-list");
                    packagePrefix = cmd.getOptionValue("package-prefix", "");
                    if (jarPath == null || criticalMethodsFile == null) {
                        System.err.println("--jar-path, --method-list are required for check-call");
                        System.exit(1);
                    }
                    CriticalMethodScanner.scanJarFile(jarPath, CriticalMethodScanner.loadCriticalMethods(criticalMethodsFile), packagePrefix);
                    break;
                case "check-reflect":
                    jarPath = cmd.getOptionValue("jar-path");
                    String reflectionMethodsFile = cmd.getOptionValue("method-list");
                    packagePrefix = cmd.getOptionValue("package-prefix", "");
                    if (jarPath == null || reflectionMethodsFile == null) {
                        System.err.println("--jar-path, --method-list are required for check-reflect");
                        System.exit(1);
                    }
                    ReflectionScanner.scanJar(jarPath, reflectionMethodsFile, packagePrefix);
                    break;
                default:
                    System.err.println("[-] Unknown task: " + task);
                    formatter.printHelp("java -jar prog-analysis.jar", options);
                    System.exit(1);
            }
        } catch (ParseException e) {
            System.err.println("[-] Parsing error: " + e.getMessage());
            formatter.printHelp("java -jar prog-analysis.jar", options);
        }
    }
}
