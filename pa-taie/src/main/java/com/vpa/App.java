package com.vpa;

import org.apache.commons.cli.*;


public class App {

    public static void main(String[] args) {
        Options options = new Options();

        options.addOption(Option.builder("j")
                .longOpt("jar")
                .hasArgs()
                .desc("Paths to the jar files (can be specified multiple times)")
                .required()
                .build());

        options.addOption(Option.builder("c")
                .longOpt("class-list")
                .hasArg()
                .desc("Path to the target class list file")
                .required()
                .build());

        options.addOption(Option.builder("o")
                .longOpt("out")
                .hasArg()
                .desc("Path to the output file")
                .required()
                .build());

        // add one for the reflection log (optional)
        options.addOption(Option.builder("r")
                .longOpt("reflection-log")
                .hasArg()
                .desc("Path to the reflection log file (optional)")
                .build());

        // add one for reflection-inference (optional)
        options.addOption(Option.builder("ri")
                .longOpt("reflection-inference")
                .hasArg()
                .desc("Reflection inference mode (solar or null)")
                .build());

        // add `--only-app` option (no argument)
        options.addOption(Option.builder("oa")
                .longOpt("only-app")
                .desc("Only analyze the application code (no library code)")
                .build());

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        try {
            CommandLine cmd = parser.parse(options, args);

            String[] jarPaths = cmd.getOptionValues("jar");
            String classListFile = cmd.getOptionValue("class-list");
            String outputFile = cmd.getOptionValue("out");
            String reflectionLog = cmd.getOptionValue("reflection-log");
            String reflectionInference = cmd.getOptionValue("reflection-inference", "solar"); // default to "solar"
            boolean onlyApp = cmd.hasOption("only-app");

            System.setProperty("plugin.classlist.file", classListFile);
            System.setProperty("plugin.output.cg.file", outputFile);

            String reflectionLogOption = reflectionLog != null
                    ? "reflection-log:" + reflectionLog + ";"
                    : "";
            
            String onlyAppCode = onlyApp ? "only-app:true;" : "only-app:false;";
            

            String reflectionInferenceOption = "reflection-inference:" + reflectionInference + ";";

            String[] acpArgs = new String[jarPaths.length * 2];
            for (int i = 0; i < jarPaths.length; i++) {
                acpArgs[i * 2] = "-acp";
                acpArgs[i * 2 + 1] = jarPaths[i];
            }

            pascal.taie.Main.main(
                    concatArrays(
                            acpArgs,
                            new String[]{
                                    "-scope", "APP",
                                    "-ap",
                                    "-java", "8",
                                    "-a", "pta=cs:ci;implicit-entries:false;dump:false;"
                                            + "plugins:[com.vpa.CustomEntryPointPlugin];"
                                            + "distinguish-string-constants:null;"
                                            + reflectionInferenceOption
                                            + reflectionLogOption
                                            + onlyAppCode,
                                    "-a", "cg=dump:false;dump-methods:false;dump-call-edges:false;"
                            }
                    )
            );

        } catch (ParseException e) {
            System.err.println(e.getMessage());
            formatter.printHelp("java com.vpa.App", options);
            System.exit(1);
        }
    }

    private static String[] concatArrays(String[] first, String[] second) {
        String[] result = new String[first.length + second.length];
        System.arraycopy(first, 0, result, 0, first.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}