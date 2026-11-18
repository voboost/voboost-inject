import test from "node:test";
import assert from "node:assert/strict";
import { auditProductionSources, auditSource, splitRegressionCases } from "./test-no-network-client.ts";

test("actual production inventory admits only its declared local/QNX transport owners",()=>auditProductionSources());
for(const [name,label,source] of splitRegressionCases())
    test(name,()=>assert.throws(()=>auditSource(label,source)));

// The ordinary owning gate always performs these against actual offline Cargo metadata.
// A retained read-only metadata capture also exercises them without holding the Cargo slot.
if(process.env.VOBOOST_TEST_CARGO_METADATA) {
    const {readFileSync}=await import("node:fs");
    const {auditDependencies,auditDependencyRegressions}=await import("./test-no-network-client.ts");
    const metadata=JSON.parse(readFileSync(process.env.VOBOOST_TEST_CARGO_METADATA,"utf8"));
    test("actual retained Cargo metadata matches the closed first-party inventory",()=>auditDependencies(metadata.packages));
    test("ten real metadata mutations cannot add or redirect clients",()=>auditDependencyRegressions(metadata.packages));
}
