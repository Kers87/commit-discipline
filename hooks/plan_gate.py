"""plan-gate: PreToolUse guard (matcher: every tool except the always-allowed core tools).

Refuses by TOOL CLASS per working phase, not per command. A command variant cannot get around
it, because the command is never read: in that phase the tool simply does not exist.

The phase is permission_mode from the hook input. The human sets it (Shift+Tab). The model can
enter Plan Mode (EnterPlanMode) but only leave it with approval (ExitPlanMode). A phase file of
our own was rejected on purpose: in a trial the model overwrote such a file with Write as soon
as it was allowed to write.

Rule 1 - Plan Mode = research phase, as an ALLOWLIST: read, search and ask only. Writing, the
  shell and every MCP tool without a read verb do not exist in this phase, so a new tool is
  closed by default. Exceptions:
  - Write/Edit on the plan file in ~/.claude/plans/ (Plan Mode writes there itself);
  - Agent only with a subagent that is itself read-only.
  Why a hook on top of Plan Mode: a hook deny holds in every permission mode, including
  bypassPermissions (measured), while the harness does not enforce the plan restrictions in
  every session setup.
Rule 2 - in EVERY mode: Write/Edit/NotebookEdit on the guards' state directory is closed. The
  guards decide on that state; a model that can write it can open its own gate.

Environment:
  COMMIT_DISCIPLINE_PLANS_DIR         plan directory (default ~/.claude/plans)
  COMMIT_DISCIPLINE_READONLY_AGENTS   extra read-only subagent names, comma-separated
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import deny, is_within, norm, read_input, state_dir  # noqa: E402

PLAN_ALLOWED = {
    'Read', 'Grep', 'Glob', 'WebFetch', 'WebSearch', 'ToolSearch', 'Skill',
    'AskUserQuestion', 'EnterPlanMode', 'ExitPlanMode', 'TodoWrite', 'TaskOutput',
    'SendMessage', 'ListAgents', 'ListMcpResourcesTool', 'ReadMcpResourceTool',
    'ReadMcpResourceDirTool', 'ListSkills', 'SearchSkills', 'ListPlugins', 'SearchPlugins',
}
# Built-in subagents whose own tool list is read-only.
PLAN_AGENTS = {'Explore', 'Plan', 'claude-code-guide'}

# An MCP tool reads when the part after the last '__' carries a read verb as a separate word
# AND no write verb. The write verb wins: 'spaces_edit_status' and 'set_view' slipped through
# on 'status' and 'view' before that rule. No recognisable verb = closed.
MCP_READ = re.compile(r'(?i)(^|[-_])(fetch|search|get|list|query|read|view|find|show|status|'
                      r'context|whoami)([-_]|$)')
MCP_WRITE = re.compile(
    r'(?i)(^|[-_])(edit|set|update|create|delete|remove|move|run|send|stop|archive|write|'
    r'upload|generate|deliver|publish|post|patch|put|rename|share|assign|unassign|like|comment|'
    r'confirm|trigger|start|spawn|install|enable|disable|clear|pin|unpin|finalize|register|'
    r'dismiss|mark|toggle|resize|close|select|switch|change|add|insert|replace|reply|resolve|'
    r'apply|execute|deploy|merge|reset|kill|cancel|approve|submit|convert|duplicate|compose|'
    r'upscale|crop|expand|cut|retouch|relight|isolate|speak|concatenate)([-_]|$)')
WRITE_TOOLS = {'Write', 'Edit', 'MultiEdit', 'NotebookEdit'}


def readonly_agents():
    extra = os.environ.get('COMMIT_DISCIPLINE_READONLY_AGENTS', '')
    return PLAN_AGENTS | {a.strip() for a in extra.split(',') if a.strip()}


def main():
    data = read_input()
    if data is None:
        return
    tool = data.get('tool_name')
    if not isinstance(tool, str) or not tool.strip():
        return
    mode = data.get('permission_mode')
    tinput = data.get('tool_input') or {}

    raw = path = None
    if tool in WRITE_TOOLS:
        raw = tinput.get('file_path') or tinput.get('notebook_path')
        path = norm(raw)

    # Rule 2: the guards' state cannot be written (all modes).
    if path and is_within(path, state_dir()):
        deny('plan-gate: %s on %s is blocked. That directory holds the state the guards decide '
             'on; only the hooks themselves write it.' % (tool, raw))

    # Rule 1: Plan Mode = research phase.
    if mode != 'plan':
        return
    if tool in PLAN_ALLOWED:
        return

    if tool == 'Agent':
        agents = readonly_agents()
        sub = tinput.get('subagent_type')
        if sub in agents:
            return
        deny("plan-gate: in Plan Mode (research phase) only a read-only subagent may start "
             "(%s). Subagent '%s' can write. Choose Explore or Plan, or finish the plan with "
             "ExitPlanMode." % (', '.join(sorted(agents)), sub or 'general-purpose (default)'))

    if tool in WRITE_TOOLS:
        plans = norm(os.environ.get('COMMIT_DISCIPLINE_PLANS_DIR')
                     or os.path.join('~', '.claude', 'plans'))
        if path and path != plans and is_within(path, plans):
            return

    if tool.startswith('mcp__'):
        short = tool.split('__')[-1]
        if not MCP_WRITE.search(short) and MCP_READ.search(short):
            return

    deny('plan-gate: in Plan Mode (research phase) %s does not exist. Only reading, searching '
         'and asking are allowed here; the plan file in ~/.claude/plans/ stays writable. Keep '
         'working read-only, or finish the plan with ExitPlanMode; after approval this gate '
         'lifts.' % tool)


if __name__ == '__main__':
    main()
