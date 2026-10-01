import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import test from "node:test";

test("evaluates nested-quantifier rules within a bounded execution time", () => {
  const source = new URL("../src/index.ts", import.meta.url).href;
  const script = `import { evaluateRules } from ${JSON.stringify(source)};
    const rules = [{id:"redos",name:"test",source:"test",category:"test",severity:"high",
      target:"body",operator:"regex",pattern:"^(a+)+$",action:"block",enabled:true}];
    const matches = evaluateRules({method:"POST",path:"/",query:"",headers:{},body:"a".repeat(10000)+"!"}, rules);
    if (matches.length !== 0) process.exit(1);`;
  assert.doesNotThrow(() => execFileSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
    timeout: 3000, stdio: "pipe"
  }));
});
