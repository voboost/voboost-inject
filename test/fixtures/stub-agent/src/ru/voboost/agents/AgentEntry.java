package ru.voboost.agents;

import android.util.Log;

/**
 * Stub AgentEntry for emulator/stubs testing (real agent runtime lives in
 * voboost-script). Implements the fixed seam documented in
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
    private static final String TAG = "voboost-stub-agent";

    /** The fixed seam the implant resolves and calls. */
    public static void init(String configPath) {
        Log.i(TAG, "AgentEntry.init seam called; configPath=" + configPath);
    }
}
