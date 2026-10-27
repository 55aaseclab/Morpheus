// @ts-nocheck
// Evaluation entry resolution for morpheus.yaml.
//
// A top-level `evaluation-entries` map names the runnable evaluations:
//   evaluation-entries:
//     evaluation-000:
//       workflow: <workflow name>        # dispatch the action to a workflow
//     evaluation-008:
//       script: evaluation/xxx.sh        # run a wrapper script (experiment
//                                        # battery); the script owns its
//                                        # side workflows and arguments
//
// `config check` validates that workflow entries point to existing
// workflows and script entries point to existing files. The `eval`
// command resolves an entry and dispatches accordingly.
const fs = require("node:fs");
const path = require("node:path");

function isPlainObject(value) {
    return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
function evaluationEntries(configValue) {
    return configValue && isPlainObject(configValue["evaluation-entries"])
        ? configValue["evaluation-entries"]
        : {};
}
function resolveEvaluationEntry(configValue, name) {
    const entries = evaluationEntries(configValue);
    const entry = entries[name];
    if (!isPlainObject(entry)) {
        return null;
    }
    if (entry.workflow && typeof entry.workflow === "string") {
        return { kind: "workflow", workflow: entry.workflow };
    }
    if (entry.script && typeof entry.script === "string") {
        return { kind: "script", script: entry.script };
    }
    throw new Error(`evaluation entry ${name} must declare workflow: or script:`);
}
function evaluationEntryIssues(configValue, configDir = null) {
    const issues = [];
    const workflows = configValue && isPlainObject(configValue.workflows) ? configValue.workflows : {};
    for (const [name, entry] of Object.entries(evaluationEntries(configValue))) {
        if (!isPlainObject(entry)) {
            issues.push({
                level: "error",
                path: `evaluation-entries.${name}`,
                message: "evaluation entry must be a map",
            });
            continue;
        }
        let resolved = null;
        try {
            resolved = resolveEvaluationEntry(configValue, name);
        }
        catch (error) {
            issues.push({
                level: "error",
                path: `evaluation-entries.${name}`,
                message: String(error && error.message ? error.message : error),
            });
            continue;
        }
        if (resolved.kind === "workflow") {
            if (!isPlainObject(workflows[resolved.workflow])) {
                issues.push({
                    level: "error",
                    path: `evaluation-entries.${name}`,
                    message: `evaluation entry points to unknown workflow: ${resolved.workflow}`,
                });
            }
            continue;
        }
        if (configDir != null) {
            const scriptPath = path.resolve(configDir, resolved.script);
            if (!fs.existsSync(scriptPath)) {
                issues.push({
                    level: "error",
                    path: `evaluation-entries.${name}`,
                    message: `evaluation entry points to missing script: ${resolved.script}`,
                });
            }
        }
    }
    return issues;
}
module.exports = {
    evaluationEntries,
    resolveEvaluationEntry,
    evaluationEntryIssues,
};
