package ru.voboost.agents;

/**
 * Stub AgentEntry for emulator/stubs testing (the real agent runtime is built
 * by the voboost agents module). Implements the fixed seam documented in
 * implant/include/agent_entry_seam.h:
 *
 *   Class:  ru.voboost.agents.AgentEntry
 *   Method: public static void init(String configPath)
 *
 * The implant calls init(String) via JNI after LSPlant init + hidden-API
 * exemption. This stub just reads + logs the config file path (the simplest
 * possible agent, mirrors the launcher-echo pattern) so we can verify the
 * injection pipeline end-to-end (ptrace -> dlopen libimplant -> ART attach ->
 * dex load -> seam call) on the emulator without the real agent runtime.
 *
 * Defensive: any throw is caught by the implant (target keeps running).
 */
public class AgentEntry {
    public static void registerModule(
            String id, String entryClass, String[] processes, ClassLoader moduleLoader) {
        if (processes == null || processes.length == 0) {
            throw new IllegalArgumentException("module processes are empty");
        }
    }

    public static void registerArtifact(String id, byte[] content) {}

    public static void registerGeneration(String generation, String catalogSha256) {}

    /** The fixed seam the implant resolves and calls. */
    public static void init(String configPath) {
        Log.info("stub-agent", "AgentEntry.init seam called; configPath=" + configPath);
    }
}
