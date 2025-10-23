package com.vpa;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.objectweb.asm.*;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class ReflectionScanner {
    private static Set<String> packagePrefixes = new HashSet<>();

    private static final Gson gson = new Gson();

    public static class CriticalMethod {
        private String owner;
        private String name;
        private String descriptor;

        public CriticalMethod() {}

        public CriticalMethod(String owner, String name, String descriptor) {
            this.owner = owner;
            this.name = name;
            this.descriptor = descriptor;
        }

        public String getOwner() { return owner; }
        public String getName() { return name; }
        public String getDescriptor() { return descriptor; }
        public void setOwner(String owner) { this.owner = owner; }
        public void setName(String name) { this.name = name; }
        public void setDescriptor(String descriptor) { this.descriptor = descriptor; }
    }

    public static class ScanResult {
        private final boolean foundReflection;
        private final List<String> detectedMethods;

        public ScanResult(boolean found, List<String> methods) {
            this.foundReflection = found;
            this.detectedMethods = methods;
        }

        public boolean isFoundReflection() { return foundReflection; }
        public List<String> getDetectedMethods() { return detectedMethods; }
    }

    private static void loadPackagePrefixes(String packagePrefixFilePath) {
        if (!packagePrefixes.isEmpty()) return;

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

    private static List<CriticalMethod> loadMethodsFromJson(String jsonPath) throws IOException {
        try (Reader reader = new FileReader(jsonPath)) {
            return gson.fromJson(reader, 
                new TypeToken<List<CriticalMethod>>(){}.getType());
        }
    }

    public static class ReflectionClassVisitor extends ClassVisitor {
        private final List<CriticalMethod> targetMethods;
        private final List<String> detectedMethods = new ArrayList<>();

        public ReflectionClassVisitor(int api, List<CriticalMethod> methods) {
            super(api);
            this.targetMethods = methods;
        }

        public List<String> getDetectedMethods() {
            return Collections.unmodifiableList(detectedMethods);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, 
                                       String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            return new MethodVisitor(api, mv) {
                @Override
                public void visitMethodInsn(int opcode, String owner, String methodName,
                                           String methodDescriptor, boolean isInterface) {
                    checkMethod(owner, methodName, methodDescriptor);
                    super.visitMethodInsn(opcode, owner, methodName, methodDescriptor, isInterface);
                }

                private void checkMethod(String owner, String name, String desc) {
                    targetMethods.stream()
                        .filter(m -> owner.equals(m.getOwner()) 
                                  && name.equals(m.getName()) 
                                  && desc.equals(m.getDescriptor()))
                        .findFirst()
                        .ifPresent(m -> detectedMethods.add(
                            String.format("%s#%s%s", owner, name, desc)));
                }
            };
        }
    }

    public static void scanJar(String jarPath, String configPath, String packagePrefix) {
        ScanResult result = null;
        loadPackagePrefixes(packagePrefix); 
        try {
            List<CriticalMethod> methods = loadMethodsFromJson(configPath);
            Set<String> detected = new HashSet<>(); // Use a Set to deduplicate results

            try (JarFile jar = new JarFile(jarPath)) {
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (!entry.getName().endsWith(".class")) continue;
                    
                    if (!packagePrefixes.isEmpty()) {
                        String className = entry.getName().replace('/', '.').replace(".class", "");
                        boolean matchedPrefix = packagePrefixes.contains(className);
                        if (!matchedPrefix) continue; // Skip if not in package prefixes
                    }

                    try (InputStream is = jar.getInputStream(entry)) {
                        ClassReader cr = new ClassReader(is);
                        ReflectionClassVisitor visitor = new ReflectionClassVisitor(Opcodes.ASM9, methods);
                        cr.accept(visitor, ClassReader.SKIP_FRAMES);
                        detected.addAll(visitor.getDetectedMethods()); // Add to the Set
                    }
                }
            }
            result = new ScanResult(!detected.isEmpty(), new ArrayList<>(detected)); // Convert Set back to List
        } catch (IOException e) {
            result = new ScanResult(false, Collections.singletonList("ERROR: " + e.getMessage()));
        }

        System.out.println(gson.toJson(result));
    }
}