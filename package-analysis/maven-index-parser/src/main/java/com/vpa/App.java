package com.vpa;
import org.apache.lucene.document.Document;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.store.FSDirectory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;

public class App {

    public static void main(String[] args) throws IOException {
        // Specify the index file path (uncompressed directory)
        File indexDir = new File("../../../workdir/mcr/central-lucene-index");

        // Open the index directory
        IndexReader reader = IndexReader.open(FSDirectory.open(indexDir));

        // Output CSV file path
        String outputCsvPath = "../../../workdir/mcr/artifacts-list.csv";

        // Open the CSV file for writing
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputCsvPath))) {
            // Write the CSV header
            writer.println("GroupId,ArtifactId,Version,Timestamp");

            // Used to store unique GAVs
            Set<String> uniqueGAVs = new HashSet<>();
            int batchSize = 100000;  // Process 10000 documents per batch
            int totalUniqueCount = 0;

            // Iterate through all documents
            for (int i = 0; i < reader.maxDoc(); i++) {
                Document doc = reader.document(i);

                // Extract the 'u' field
                String uField = doc.get("u");
                if (uField != null) {
                    // Split the 'u' field by '|' to extract GAV information
                    String[] parts = uField.split("\\|");
                    if (parts.length >= 4 && parts[3].equals("NA")) {
                        String iField = doc.get("i");
                        String []iParts = iField.split("\\|");
                        String timestamp = iParts[1];
                        String groupId = parts[0];
                        String artifactId = parts[1];
                        String version = parts[2];
                        // remove versions with double quote
                        if (version.contains("\"")) {
                            continue;
                        }

                        // Combine GAV and store it in the set
                        String gav = String.format("%s,%s,%s,%s", groupId, artifactId, version, timestamp);
                        uniqueGAVs.add(gav);
                    }
                }

                // Write and clear the set every batch of documents
                if (i > 0 && i % batchSize == 0) {
                    totalUniqueCount += uniqueGAVs.size();
                    for (String gav : uniqueGAVs) {
                        writer.println(gav);
                    }
                    // actual size
                    int actualSize = uniqueGAVs.size();
                    uniqueGAVs.clear();  // Clear the set to free memory
                    System.out.println("Processed " + actualSize + " GAVs...");
                }
            }

            // Write the last batch
            totalUniqueCount += uniqueGAVs.size();
            for (String gav : uniqueGAVs) {
                writer.println(gav);
            }

            System.out.println("Artifacts list saved to: " + outputCsvPath);
            System.out.println("Total unique GAVs: " + totalUniqueCount);
        }

        // Close the index reader
        reader.close();
    }
}
