package com.vpa;

import org.objectweb.asm.*;

import java.io.*;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CriticalMethodScanner {
    private static Set<String> packagePrefixes = new HashSet<>();

    public static class CriticalMethod {
        private final String owner;
        private final String name;
        private final String descriptor;

        public CriticalMethod(String owner, String name, String descriptor) {
            this.owner = owner;
            this.name = name;
            this.descriptor = descriptor;
        }

        public String getOwner() {
            return owner;
        }

        public String getName() {
            return name;
        }

        public String getDescriptor() {
            return descriptor;
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

    public static CriticalMethod parseCriticalMethod(String line) {
        line = line.trim();
        if (!line.startsWith("<") || !line.endsWith(">")) {
            throw new IllegalArgumentException("Line format error, should be surrounded by < and >: " + line);
        }
        String content = line.substring(1, line.length() - 1).trim();
        String[] parts = content.split(":", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Line format error, missing colon separator: " + line);
        }
        String className = parts[0].trim();
        String methodInfo = parts[1].trim();

        Pattern pattern = Pattern.compile("(\\S+)\\s+(\\S+)\\((.*)\\)");
        Matcher matcher = pattern.matcher(methodInfo);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("Method signature format error: " + methodInfo);
        }
        String returnType = matcher.group(1).trim();
        String methodName = matcher.group(2).trim();
        String params = matcher.group(3).trim();
        String methodDescriptor = generateMethodDescriptor(params, returnType);
        String internalClassName = className.replace('.', '/');
        return new CriticalMethod(internalClassName, methodName, methodDescriptor);
    }

    public static String generateMethodDescriptor(String params, String returnType) {
        StringBuilder sb = new StringBuilder();
        sb.append("(");
        if (!params.isEmpty()) {
            String[] paramArray = params.split(",");
            for (String param : paramArray) {
                sb.append(convertToDescriptor(param.trim()));
            }
        }
        sb.append(")");
        sb.append(convertToDescriptor(returnType));
        return sb.toString();
    }

    public static String convertToDescriptor(String type) {
        switch (type) {
            case "byte": return "B";
            case "char": return "C";
            case "double": return "D";
            case "float": return "F";
            case "int": return "I";
            case "long": return "J";
            case "short": return "S";
            case "boolean": return "Z";
            case "void": return "V";
            default:
                if (type.endsWith("[]")) {
                    String elementType = type.substring(0, type.length() - 2).trim();
                    return "[" + convertToDescriptor(elementType);
                }
                return "L" + type.replace('.', '/') + ";";
        }
    }

    public static List<CriticalMethod> loadCriticalMethods(String filePath) {
        List<CriticalMethod> list = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                try {
                    CriticalMethod cm = parseCriticalMethod(line);
                    list.add(cm);
                } catch (IllegalArgumentException e) {
                    // Report error but continue
                    System.err.println("[-] Error parsing line: " + line);
                    System.err.println(e.getMessage());
                }
            }
        } catch (IOException e) {
            // Do not print any logs on error
        }
        return list;
    }

    public static class CriticalMethodClassVisitor extends ClassVisitor {
        private final List<CriticalMethod> criticalMethods;
        private boolean found = false;

        public CriticalMethodClassVisitor(int api, List<CriticalMethod> criticalMethods) {
            super(api);
            this.criticalMethods = criticalMethods;
        }

        public boolean isFound() {
            return found;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            return new MethodVisitor(Opcodes.ASM9, mv) {
                @Override
                public void visitMethodInsn(int opcode, String owner, String methodName, String methodDesc, boolean isInterface) {
                    for (CriticalMethod cm : criticalMethods) {
                        if (owner.equals(cm.getOwner()) && methodName.equals(cm.getName()) && methodDesc.equals(cm.getDescriptor())) {
                            found = true;
                        }
                    }
                    super.visitMethodInsn(opcode, owner, methodName, methodDesc, isInterface);
                }
            };
        }
    }

    public static void scanJarFile(String jarPath, List<CriticalMethod> criticalMethods, String packagePrefixFilePath) {
        loadPackagePrefixes(packagePrefixFilePath); // Ensure package prefixes are loaded
        boolean anyFound = false;
        try (JarFile jarFile = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements() && !anyFound) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    // Convert the entry name to a fully qualified class name
                    String className = entry.getName().replace('/', '.').replace(".class", "");

                    if (!packagePrefixes.isEmpty()) {
                        // Check if the class belongs to one of the package prefixes
                        boolean matchesPrefix = packagePrefixes.contains(className);
                        if (!matchesPrefix) {
                            continue; // Skip classes not in the specified package prefixes
                        }
                    }
                    
                    try (InputStream is = jarFile.getInputStream(entry)) {
                        byte[] classBytes = readAllBytes(is);
                        ClassReader cr = new ClassReader(classBytes);
                        CriticalMethodClassVisitor visitor = new CriticalMethodClassVisitor(Opcodes.ASM9, criticalMethods);
                        cr.accept(visitor, ClassReader.SKIP_FRAMES);
                        if (visitor.isFound()) {
                            anyFound = true;
                            break;
                        }
                    } catch (IOException e) {
                        // Ignore individual class read exceptions
                    }
                }
            }
        } catch (IOException e) {
            // Ignore jar file read exceptions
        }
        // Only output the final result
        System.out.println(anyFound ? "YES" : "NO");
    }

    private static byte[] readAllBytes(InputStream is) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[4096];
        int nRead;
        while ((nRead = is.read(data)) != -1) {
            buffer.write(data, 0, nRead);
        }
        return buffer.toByteArray();
    }
}
