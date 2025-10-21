package com.vpa;

import org.apache.maven.model.Dependency;
import org.apache.maven.model.Parent;
import org.apache.maven.model.Repository;
import org.apache.maven.model.building.FileModelSource;
import org.apache.maven.model.resolution.ModelResolver;
import org.apache.maven.model.building.ModelSource2;
import org.apache.maven.model.resolution.UnresolvableModelException;

import java.io.File;

/**
 * Offline ModelResolver, suitable for local POM directory parsing, will not access remote repositories.
 */
public class OfflineModelResolver implements ModelResolver {
    private final String pomsBaseDir;

    /**
     * @param pomsBaseDir The root directory where local POM files are stored, such as "poms"
     */
    public OfflineModelResolver(String pomsBaseDir) {
        this.pomsBaseDir = pomsBaseDir;
    }

    /**
     * Resolve the POM file path based on Parent.
     */
    @Override
    public ModelSource2 resolveModel(Parent parent) throws UnresolvableModelException {
        return resolveModel(parent.getGroupId(), parent.getArtifactId(), parent.getVersion());
    }

    /**
     * Directly resolve POM in GAV format.
     */
    @Override
    public ModelSource2 resolveModel(String groupId, String artifactId, String version)
            throws UnresolvableModelException {
        // Do not convert groupId, directly construct the path
        String pomPath = pomsBaseDir + "/" + groupId + "/" + artifactId + "/" + version + "/" + artifactId + "-" + version + ".pom";
        // print the path
        // System.out.println(pomPath);
        File pomFile = new File(pomPath);

        if (!pomFile.exists()) {
            throw new UnresolvableModelException(
                    "Unable to resolve POM: " + groupId + ":" + artifactId + ":" + version,
                    groupId, artifactId, version
            );
        }
        return new FileModelSource(pomFile);
    }

    /**
     * Resolve the POM file of the Dependency.
     */
    @Override
    public ModelSource2 resolveModel(Dependency dependency) throws UnresolvableModelException {
        return resolveModel(dependency.getGroupId(), dependency.getArtifactId(), dependency.getVersion());
    }

    /**
     * Add repository (usually ignored in offline mode).
     */
    @Override
    public void addRepository(Repository repository) {
        // No need to add additional repositories in offline mode
    }

    /**
     * Add repository (usually ignored in offline mode).
     */
    @Override
    public void addRepository(Repository repository, boolean replace) {
        // No need to add additional repositories in offline mode
    }

    /**
     * Copy the current ModelResolver instance (must be implemented).
     */
    @Override
    public ModelResolver newCopy() {
        return new OfflineModelResolver(this.pomsBaseDir);
    }
}
