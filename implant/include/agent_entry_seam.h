/*
 * agent_entry_seam.h — the fixed C++→Java crossing contract.
 *
 * The implant enters Java through exactly ONE seam. This header documents
 * that contract so both sides (implant C++ here, AgentEntry Java in
 * voboost-script) agree on the signature.
 *
 * Contract:
 *   Class:   ru.voboost.agents.AgentEntry
 *   Method:  public static void init(String configPath)
 *
 * The implant calls this via JNI after LSPlant initialization and the
 * hidden-API exemption (setHiddenApiExemptions("L")).
 *
 * configPath: the channel-B config file path (media_rw_data_file,
 *   world-readable). The agent runtime reads it on init and watches it
 *   for live updates (inotify). voboost-inject writes it at injection
 *   and rewrites it atomically (write-tmp+rename).
 *
 * Defensive: a throwing AgentEntry.init (or unresolved class/method) is
 *   caught by the implant — the exception is cleared and the target keeps
 *   running. The seam SHALL NOT crash the target.
 *
 * This seam is agent-set-independent: adding/removing/renaming agents
 *   does NOT require rebuilding the implant, because the implant names no
 *   agent-specific symbol.
 */
#ifndef AGENT_ENTRY_SEAM_H
#define AGENT_ENTRY_SEAM_H

/* The fixed class + method — used by implant.cpp JNI calls.
 * These are compile-time constants; changing them requires coordinated
 * changes in voboost-script (the AgentEntry class). */
#define AGENT_ENTRY_CLASS_NAME  "ru/voboost/agents/AgentEntry"
#define AGENT_ENTRY_METHOD_NAME "init"
#define AGENT_ENTRY_METHOD_SIG  "(Ljava/lang/String;)V"

/* The Java equivalent (for documentation — the real class is in voboost-script):
 *
 *   package ru.voboost.agents;
 *
 *   public class AgentEntry {
 *       public static void init(String configPath) {
 *           // agent runtime bootstrap: parse config, discover agents,
 *           // install hooks via LSPlant, set up config-watcher (inotify)
 *       }
 *   }
 */

#endif /* AGENT_ENTRY_SEAM_H */
