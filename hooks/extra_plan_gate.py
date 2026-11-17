"""Slooppas c-711 op commit-discipline 0.1.2: extra gevallen voor plan_gate.py.

CASES-vorm: (naam, payload, verwacht). Alleen bestanden in %TEMP%.
"""

import ctypes
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _testlib import Report, run_hook  # noqa: E402
from test_plan_gate import ENV, HOOK, PLANS, ROOT, STATE, j, p  # noqa: E402

BS = chr(92)
os.makedirs(PLANS, exist_ok=True)
TSV = j(STATE, 'green-tests.tsv')
with open(TSV, 'w') as f:
    f.write('x\n')
LINK = j(ROOT, 'harmless.tsv')
try:
    os.link(TSV, LINK)                    # harde link naar het bewijsbestand
    HAVE_LINK = True
except OSError as e:
    print('INFO  hardlink niet gemaakt:', e)
    HAVE_LINK = False

DEEP = [[]]
for _ in range(3000):
    DEEP = [DEEP]


def vol_guid(drive):
    buf = ctypes.create_unicode_buffer(64)
    ok = ctypes.windll.kernel32.GetVolumeNameForVolumeMountPointW(drive + BS, buf, 64)
    return buf.value if ok else None


def dos_device(drive):
    buf = ctypes.create_unicode_buffer(512)
    n = ctypes.windll.kernel32.QueryDosDeviceW(drive, buf, 512)
    return buf.value if n else None


CASES = [
    ('S-trailing-dot', p('default', 'Write', {'file_path': STATE + '.' + BS + 'x'}), 'deny'),
    ('S-trailing-space', p('default', 'Write', {'file_path': STATE + ' ' + BS + 'x'}), 'deny'),
    ('S-dot-unc', p('default', 'Write', {'file_path': BS * 2 + '.' + BS + 'UNC' + BS + 'localhost' + BS
                                          + STATE[0] + '$' + STATE[2:] + BS + 'x'}), 'deny'),
    ('S-multiedit', p('default', 'MultiEdit', {'file_path': TSV}), 'deny'),
    ('S-notebook', p('default', 'NotebookEdit', {'notebook_path': j(STATE, 'x.ipynb')}), 'deny'),
    ('S-ads-stream', p('default', 'Write', {'file_path': TSV + ':extra'}), 'deny'),
    ('P-deep-json-mcp-write', '{"hook_event_name":"PreToolUse","permission_mode":"plan",'
     '"tool_name":"mcp__notion__notion-update-page","tool_input":{"data":'
     + '[' * 3000 + ']' * 3000 + '}}', 'deny'),
    ('P-deep-json-bash', '{"hook_event_name":"PreToolUse","permission_mode":"plan",'
     '"tool_name":"Bash","tool_input":{"command":"echo","x":' + '[' * 3000 + ']' * 3000 + '}}', 'deny'),
    ('P-shallow-json-mcp-write', '{"hook_event_name":"PreToolUse","permission_mode":"plan",'
     '"tool_name":"mcp__notion__notion-update-page","tool_input":{"data":'
     + '[' * 50 + ']' * 50 + '}}', 'deny'),
    ('P-mcp-save', p('plan', 'mcp__x__context_save'), 'deny'),
    ('P-mcp-fetch-and-store', p('plan', 'mcp__x__fetch_and_store'), 'deny'),
    ('P-mcp-get-and-sync', p('plan', 'mcp__x__get_and_sync'), 'deny'),
    ('P-agent-lowercase-explore', p('plan', 'Agent', {'subagent_type': 'explore'}), 'deny'),
    ('P-workflow', p('plan', 'Workflow', {'script': 'x'}), 'deny'),
    ('P-artifact', p('plan', 'Artifact', {'action': 'publish'}), 'deny'),
    ('P-plans-dir-junction-escape', p('plan', 'Write', {'file_path': j(PLANS, '..', 'plans2', 'x.md')}), 'deny'),
    # gewoon gebruik dat door moet
    ('N-plan-read-page', p('plan', 'mcp__Claude_Browser__read_page'), 'allow'),
    ('N-plan-get-session', p('plan', 'mcp__ccd_session_mgmt__get_session'), 'allow'),
    ('N-plan-navigate-closed', p('plan', 'mcp__Claude_Browser__navigate'), 'deny'),
    ('N-plan-subdir-plan', p('plan', 'Write', {'file_path': j(PLANS, 'sub', 'a.md')}), 'allow'),
    ('N-default-edit-project', p('default', 'Edit', {'file_path': j(ROOT, 'project', 'a.py')}), 'allow'),
    ('N-default-write-state-sibling', p('default', 'Write', {'file_path': j(ROOT, 'state-old', 'x')}), 'allow'),
]
if HAVE_LINK:
    CASES.append(('S-hardlink-to-evidence', p('default', 'Write', {'file_path': LINK}), 'deny'))
g = vol_guid(STATE[:2])
if g:
    CASES.append(('S-volume-guid', p('default', 'Write', {'file_path': g + STATE[3:] + BS + 'x'}), 'deny'))
d = dos_device(STATE[:2])
if d:
    CASES.append(('S-globalroot', p('default', 'Write',
                                    {'file_path': BS * 2 + '?' + BS + 'GLOBALROOT' + d + STATE[2:] + BS + 'x'}),
                  'deny'))


def main():
    r = Report('plan-gate extra: %d checks' % len(CASES))
    for name, payload, want in CASES:
        try:
            got = run_hook(HOOK, payload, ENV)
        except RuntimeError as e:
            got = 'crash: ' + str(e).splitlines()[-1][:100]
        r.check(name, got == want, 'verwacht %s, kreeg %s' % (want, got) if got != want else '')
    r.finish()


if __name__ == '__main__':
    main()
