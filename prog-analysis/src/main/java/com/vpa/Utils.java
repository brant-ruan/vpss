package com.vpa;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.FileWriter;
import java.io.IOException;
import java.util.logging.Logger;
import com.google.gson.JsonArray;


public class Utils {
    private static final Logger log = LoggerFactory.getLogger();

    /* Save JSON object to file */
    public static void saveJsonToFile(JsonObject json, String filePath) {
        try (FileWriter writer = new FileWriter(filePath)) {
            new Gson().newBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(json, writer);
            log.info("JSON object saved to file: " + filePath);
        } catch (IOException e) {
            log.severe("Failed to save JSON object to file: " + e.getMessage());
        }
    }

    public static void saveListJsonToFile(JsonArray json, String filePath) {
        try (FileWriter writer = new FileWriter(filePath)) {
            new Gson().newBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(json, writer);
            log.info("JSON object saved to file: " + filePath);
        } catch (IOException e) {
            log.severe("Failed to save JSON object to file: " + e.getMessage());
        }
    }
}