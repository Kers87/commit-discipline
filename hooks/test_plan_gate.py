"""Tests for plan_gate.py.

Run:  python hooks/test_plan_gate.py
      python hooks/test_plan_gate.py --self-test   (proves per rule that the guard CAN turn red)
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testlib import HERE, Report, mutated_copy, run_hook  # noqa: E402

HOOK = os.path.join(HERE, 'plan_gate.py')
ROOT = tempfile.mkdtemp(prefix='cd-plan-')
PROJ = os.path.join(ROOT, 'project')
PLANS = os.path.join(ROOT, 'plans')
STATE = os.path.join(ROOT, 'state')
ENV = {'COMMIT_DISCIPLINE_PLANS_DIR': PLANS, 'COMMIT_DISCIPLINE_STATE_DIR': STATE,
       'CLAUDE_PROJECT_DIR': PROJ}


def j(*parts):
    return os.path.join(*parts)


def p(mode, tool, tinput=None):
    return {'hook_event_name': 'PreToolUse', 'session_id': 'test', 'permission_mode': mode,
            'tool_name': tool, 'tool_input': tinput or {}}


# name, group (for the self-test), payload, expected
CASES = [
    # deny: Plan Mode, writing and the shell do not exist
    ('deny-plan-write', 'plan-write', p('plan', 'Write', {'file_path': j(PROJ, 'x.md')}), 'deny'),
    ('deny-plan-edit', 'plan-write', p('plan', 'Edit', {'file_path': j(PROJ, 'README.md')}), 'deny'),
    ('deny-plan-notebook', 'plan-write', p('plan', 'NotebookEdit', {'notebook_path': j(PROJ, 'x.ipynb')}), 'deny'),
    ('deny-plan-traversal', 'plan-write', p('plan', 'Write', {'file_path': j(PLANS, '..', 'escaped.md')}), 'deny'),
    ('deny-plan-bash', 'plan-default', p('plan', 'Bash', {'command': 'echo hi'}), 'deny'),
    ('deny-plan-powershell', 'plan-default', p('plan', 'PowerShell', {'command': 'Write-Output hi'}), 'deny'),
    ('deny-plan-monitor', 'plan-default', p('plan', 'Monitor', {'command': 'ls'}), 'deny'),
    ('deny-plan-unknown-tool', 'plan-default', p('plan', 'NewToolFrom2027'), 'deny'),
    # deny: Plan Mode, MCP with a write verb or without a read verb
    ('deny-plan-notion-update', 'plan-default', p('plan', 'mcp__notion__notion-update-page'), 'deny'),
    ('deny-plan-notion-create', 'plan-default', p('plan', 'mcp__notion__notion-create-pages'), 'deny'),
    ('deny-plan-images-generate', 'plan-default', p('plan', 'mcp__media__images_generate'), 'deny'),
    ('deny-plan-browser-computer', 'plan-mcp', p('plan', 'mcp__browser__computer', {'action': 'left_click'}), 'deny'),
    ('deny-plan-account-balance', 'plan-mcp', p('plan', 'mcp__media__account_balance'), 'deny'),
    # a write tool with a read word in its name
    ('deny-plan-edit-status', 'plan-mcp-write', p('plan', 'mcp__media__spaces_edit_status'), 'deny'),
    ('deny-plan-set-view', 'plan-mcp-write', p('plan', 'mcp__sidebar__set_view'), 'deny'),
    # deny: Plan Mode, a subagent that can write
    ('deny-plan-agent-gp', 'plan-agent', p('plan', 'Agent', {'subagent_type': 'general-purpose'}), 'deny'),
    ('deny-plan-agent-default', 'plan-agent', p('plan', 'Agent', {'prompt': 'x'}), 'deny'),
    # deny: the guards' state, in every mode
    ('deny-state-write-default', 'state', p('default', 'Write', {'file_path': j(STATE, 'green-tests.tsv')}), 'deny'),
    ('deny-state-edit-bypass', 'state', p('bypassPermissions', 'Edit', {'file_path': j(STATE, 'x')}), 'deny'),
    ('deny-state-slash-accept', 'state', p('acceptEdits', 'Write', {'file_path': STATE.replace('\\', '/') + '/x'}), 'deny'),
    ('deny-state-traversal', 'state', p('default', 'Write', {'file_path': j(ROOT, 'tmp', '..', 'state', 'x')}), 'deny'),
    # allow: Plan Mode, read, search, ask
    ('allow-plan-read', '', p('plan', 'Read', {'file_path': j(PROJ, 'README.md')}), 'allow'),
    ('allow-plan-websearch', '', p('plan', 'WebSearch', {'query': 'x'}), 'allow'),
    ('allow-plan-exitplanmode', '', p('plan', 'ExitPlanMode'), 'allow'),
    ('allow-plan-ask', '', p('plan', 'AskUserQuestion'), 'allow'),
    ('allow-plan-agent-explore', '', p('plan', 'Agent', {'subagent_type': 'Explore'}), 'allow'),
    ('allow-plan-notion-fetch', '', p('plan', 'mcp__notion__notion-fetch'), 'allow'),
    ('allow-plan-notion-query', '', p('plan', 'mcp__notion__notion-query-data-sources'), 'allow'),
    ('allow-plan-browser-text', '', p('plan', 'mcp__browser__get_page_text'), 'allow'),
    ('allow-plan-plan-file', '', p('plan', 'Write', {'file_path': j(PLANS, 'my-plan.md')}), 'allow'),
    ('allow-plan-session-status', '', p('plan', 'mcp__notion__notion-get-session-status'), 'allow'),
    ('allow-plan-meeting-query', '', p('plan', 'mcp__notion__notion-query-meeting-notes'), 'allow'),
    # allow: outside Plan Mode the research phase does not apply
    ('allow-default-write', '', p('default', 'Write', {'file_path': j(PROJ, 'x.md')}), 'allow'),
    ('allow-accept-bash', '', p('acceptEdits', 'Bash', {'command': 'echo hi'}), 'allow'),
    ('allow-bypass-powershell', '', p('bypassPermissions', 'PowerShell', {'command': 'x'}), 'allow'),
    ('allow-near-state', '', p('default', 'Write', {'file_path': j(ROOT, 'statement.md')}), 'allow'),
    # allow: fail open
    ('allow-no-json', '', 'this is not json', 'allow'),
    ('allow-no-tool-name', '', {'permission_mode': 'plan'}, 'allow'),
]


def main():
    r = Report('plan-gate: %d checks' % (len(CASES) + 1))
    for name, _, payload, want in CASES:
        got = run_hook(HOOK, payload, ENV)
        r.check(name, got == want, got if got != want else '')
    extra = dict(ENV, COMMIT_DISCIPLINE_READONLY_AGENTS='my-reader, other')
    got = run_hook(HOOK, p('plan', 'Agent', {'subagent_type': 'my-reader'}), extra)
    r.check('allow-plan-configured-readonly-agent', got == 'allow', got)

    if '--self-test' in sys.argv[1:]:
        r.section('self-test: break one rule at a time and demand that exactly its checks turn red')
        mutations = [
            ('write-verb-ignored', ['plan-mcp-write'],
             'if not MCP_WRITE.search(short) and MCP_READ.search(short):',
             'if MCP_READ.search(short):'),
            ('plan-gate-off', ['plan-write', 'plan-default', 'plan-mcp', 'plan-mcp-write', 'plan-agent'],
             "if mode != 'plan':\n        return", 'return'),
            ('state-gate-off', ['state'],
             'if path and is_within(path, state_dir()):', 'if False:'),
            ('mcp-all-readable', ['plan-mcp'],
             "MCP_READ = re.compile(r'(?i)(^|[-_])(fetch|",
             "MCP_READ = re.compile(r'(?i)|(^|[-_])(fetch|"),
            ('plan-file-anywhere', ['plan-write'],
             'if path and path != plans and is_within(path, plans):', 'if path:'),
            ('any-agent-allowed', ['plan-agent'],
             'if sub in agents:\n            return', 'return'),
        ]
        for mname, groups, old, new in mutations:
            _, broken = mutated_copy('plan_gate.py', old, new)
            if broken is None:
                r.check('self-test %s' % mname, False, 'mutation anchor not found')
                continue
            target = [c for c in CASES if c[1] in groups]
            flipped = sum(run_hook(broken, c[2], ENV) == 'allow' for c in target)
            r.check('self-test %s' % mname, flipped == len(target),
                    '%d of %d deny checks turned red' % (flipped, len(target)))
    r.finish()


if __name__ == '__main__':
    main()
