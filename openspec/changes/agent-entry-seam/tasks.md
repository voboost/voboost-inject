## 1. Seam invocation in the implant

- [ ] 1.1 After LSPlant init, resolve `ru.voboost.agents.AgentEntry` and its
      static `init(String)` via JNI
- [ ] 1.2 Apply the hidden-API exemption (`setHiddenApiExemptions("L")`) before
      the call
- [ ] 1.3 Call `AgentEntry.init(configPath)` with the channel-B config file path
      passed to `implant_init`
- [ ] 1.4 Reference no agent-specific class or method anywhere in the implant

## 2. Defensive invocation

- [ ] 2.1 Wrap the seam call: on pending JNI exception or unresolved
      class/method, clear the exception and return without crashing the target
- [ ] 2.2 Report a seam failure as an injection failure for device-safety
      accounting

## 3. Validate

- [ ] 3.1 `npx @fission-ai/openspec validate agent-entry-seam --strict`
- [ ] 3.2 Device test: seam runs agents (reflection works); a deliberately
      throwing/absent `AgentEntry` is survived by the target and reported
