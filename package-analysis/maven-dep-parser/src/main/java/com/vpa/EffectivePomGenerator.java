package com.vpa;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.concurrent.ForkJoinPool;

import org.apache.maven.model.Model;
import org.apache.maven.model.building.*;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class EffectivePomGenerator {
    public static void main(String[] args) {
        String pomsBaseDir = "../../../workdir/poms";
        String logFilePath = "../../../workdir/failed_poms.log";
        String depsBaseDir = "../../../workdir/kb/deps";

        // Specify the number of threads (e.g., 4 threads)
        int numThreads = 20;
        ForkJoinPool customThreadPool = new ForkJoinPool(numThreads);

        try (Stream<Path> paths = Files.walk(Paths.get(pomsBaseDir))) {
            customThreadPool.submit(() -> 
                paths.filter(Files::isRegularFile)
                     .filter(path -> path.toString().endsWith(".pom"))
                     .parallel() // Enable parallel processing
                     .forEach(pomPath -> {
                         try {
                             File pomFile = pomPath.toFile();
                             String gav = parsePom(pomFile, pomsBaseDir, depsBaseDir, logFilePath);
                             // Uncomment if you want to log processed POMs
                         } catch (Exception e) {
                             System.err.println("Failed to process POM: " + pomPath);
                             // Uncomment to log exceptions
                             // saveExceptionToLog(logFilePath, pomPath.toString(), e);
                         }
                     })
            ).join(); // Wait for all tasks to complete
        } catch (IOException e) {
            System.err.println("Error while accessing POM files.");
            e.printStackTrace();
        } finally {
            customThreadPool.shutdown(); // Shutdown the thread pool
        }
        System.out.println("Dependency extraction completed.");
    }

    private static String parsePom(File pomFile, String pomsBaseDir, String depsBaseDir, String logFilePath) {
        try {
            ModelBuildingRequest request = new DefaultModelBuildingRequest();
            request.setPomFile(pomFile);
            request.setProcessPlugins(false);
            request.setProfiles(Collections.emptyList());
            request.setValidationLevel(ModelBuildingRequest.VALIDATION_LEVEL_MINIMAL);
            request.setModelResolver(new OfflineModelResolver(pomsBaseDir));

            Properties systemProperties = new Properties();
            systemProperties.setProperty("java.version", "1.8");
            systemProperties.setProperty("java.specification.version", "1.8");
            request.setSystemProperties(systemProperties);

            ModelBuildingResult result = new DefaultModelBuilderFactory().newInstance().build(request);
            Model effectiveModel = result.getEffectiveModel();

            String groupId = effectiveModel.getGroupId();
            String artifactId = effectiveModel.getArtifactId();
            String version = effectiveModel.getVersion();
            String gav = groupId + ":" + artifactId + ":" + version;

            File outputFile = new File(depsBaseDir, groupId + "/" + artifactId + "/" + version + "/dependencies.json");
            if (outputFile.exists()) {
                // print skip
                // System.out.println("Skip: " + gav);
                return gav; // Skip if already processed
            }

            List<String> dependencies = effectiveModel.getDependencies().stream()
            .filter(dep -> {
                String scope = dep.getScope();
                // Include only compile and runtime dependencies
                return scope == null || scope.isEmpty() || scope.equals("compile") || scope.equals("runtime");
            })
            .map(dep -> dep.getGroupId() + ":" + dep.getArtifactId() + ":" + (dep.getVersion() != null ? dep.getVersion() : "UNKNOWN"))
            .collect(Collectors.toList());

            saveToJson(outputFile, gav, dependencies);
            System.out.println("Processed: " + gav);

            return gav;
        } catch (ModelBuildingException e) {
            // System.err.println("Error processing POM: " + pomFile.getAbsolutePath());
            // saveExceptionToLog(logFilePath, pomFile.getAbsolutePath(), e);
            return null;
        }
    }

    private static void saveToJson(File outputFile, String gav, List<String> dependencies) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try {
            outputFile.getParentFile().mkdirs(); // Ensure directory structure exists
            try (FileWriter writer = new FileWriter(outputFile)) {
                Map<String, List<String>> data = new HashMap<>();
                data.put(gav, dependencies);
                gson.toJson(data, writer);
            }
        } catch (IOException e) {
            System.err.println("Failed to save dependencies JSON: " + outputFile.getAbsolutePath());
            e.printStackTrace();
        }
    }

    private static void saveExceptionToLog(String logFilePath, String pomPath, Exception e) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(logFilePath, true))) {
            writer.println("Failed to process POM: " + pomPath);
            // e.printStackTrace(writer);
            // writer.println("--------------------------------------");
        } catch (IOException ex) {
            System.err.println("Failed to save failed POMs log.");
            ex.printStackTrace();
        }
    }
}
