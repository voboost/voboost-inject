/*
 * agent_entry_seam.h — the fixed C++→Java crossing contract.
 *
 * The implant enters Java through exactly ONE seam. This header documents
 * that contract so both sides (implant C++ here, AgentEntry Java in
 * voboost) agree on the signature.
 *
 * Contract:
 *   Class:   ru.voboost.agents.AgentEntry
 *   Method:  public static void init(String desiredJson)
 *
 * The implant calls this via JNI after LSPlant initialization and the
 * hidden-API exemption (setHiddenApiExemptions("L")).
 *
 * desiredJson: the strict resident whole-state document from the bounded
 *   process-bound bootstrap envelope. Modules and artifacts are delivered
 *   through memfds built from the same envelope; no root path is exposed.
 *
 * Defensive: a throwing AgentEntry.init (or unresolved class/method) is
 *   caught by the implant — the exception is cleared and the target keeps
 *   running. The seam SHALL NOT crash the target.
 *
 * Observable agent-init result (early-boot readiness): the agent cannot be
 *   reached until the host Application is bound
 *   (ActivityThread.currentApplication() != null). During early boot that
 *   value is null, so the implant SHALL NOT treat the missing Application as
 *   terminal success. The seam layer reports a distinct Deferred outcome for
 *   that case (see IMPLANT_INIT_DEFERRED / IMPLANT_INIT_FAILED below) so the
 *   daemon can apply a bounded same-live-PID retry instead of marking the
 *   agent active on native-load success alone. The retry is driven by a real
 *   condition (re-polling currentApplication), never by a blind fixed delay.
 *
 * This seam is agent-set-independent: adding/removing/renaming agents
 *   does NOT require rebuilding the implant, because the implant names no
 *   agent-specific symbol.
 */
#ifndef AGENT_ENTRY_SEAM_H
#define AGENT_ENTRY_SEAM_H

/* The fixed class + method — used by implant.cpp JNI calls.
 * These are compile-time constants; changing them requires coordinated
 * changes in the voboost app (the AgentEntry class in the :agents module). */
#define AGENT_ENTRY_CLASS_NAME  "ru/voboost/agents/AgentEntry"
#define AGENT_ENTRY_METHOD_NAME "init"
#define AGENT_ENTRY_METHOD_SIG  "(Ljava/lang/String;)V"
#define AGENT_ENTRY_REGISTER_METHOD_NAME "registerModule"
#define AGENT_ENTRY_REGISTER_METHOD_SIG \
        "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/ClassLoader;)V"

/* implant_init return-value contract (observed by the injector and daemon).
 *
 * implant_init returns an int:
 *   >= 0                          a valid target-local agent-log pipe read-end
 *                                 fd; the agent was reached (Ok). The daemon
 *                                 still MUST wait for strict agent status
 *                                 before reporting Active.
 *   IMPLANT_INIT_DEFERRED         the agent was NOT reached because the host
 *                                 Application was not bound within the
 *                                 bounded early-boot re-poll window. Retryable
 *                                 on the SAME live PID: a Deferred attempt
 *                                 does NOT set the re-entry guard, so the
 *                                 daemon may re-inject while /proc/<pid>
 *                                 exists.
 *   IMPLANT_INIT_FAILED           the agent load failed hard after the native
 *                                 payload loaded (dex read/classloader/seam
 *                                 resolution). Not retryable; the daemon
 *                                 reports Failed.
 *
 * Other negative values are reserved for future hard-failure codes. Any
 * negative value that is not IMPLANT_INIT_DEFERRED is treated as a
 * non-retryable hard failure by the daemon.
 *
 * These distinct negative sentinels are chosen outside the valid fd space
 * (fds are >= 0) and below -1 so the injector can tell "no log pipe but ok"
 * (-1) apart from "deferred" (-1000) and "hard failed" (-1001).
 */
#define IMPLANT_INIT_DEFERRED  (-1000)
#define IMPLANT_INIT_FAILED    (-1001)
#define IMPLANT_INIT_PIPE_OK   (-1002)
#define IMPLANT_INIT_REBOUND   (-1003)
#define IMPLANT_INIT_STAGED (-1004)

/* Outcome of load_and_call_agent, reported up to implant_init so it can pick
 * the right return sentinel. */
enum AgentLoadResult {
    AGENT_LOAD_OK       = 0, /* dex loaded + AgentEntry.init reached */
    AGENT_LOAD_DEFERRED = 1, /* currentApplication() null after bounded re-poll */
    AGENT_LOAD_FAILED   = 2, /* dex/classloader/seam resolution hard failure */
};

/* The Java equivalent (for documentation — the real class is in voboost):
 *
 *   package ru.voboost.agents;
 *
 *   public class AgentEntry {
 *       public static void registerModule(
 *               String id, String entryClass, String[] processes, ClassLoader loader) { ... }
 *       public static void init(String desiredJson) {
 *           // parse strict whole state, start registered modules and consume
 *           // later framed desired-state updates from the bound pipe
 *       }
 *   }
 */

#endif /* AGENT_ENTRY_SEAM_H */
