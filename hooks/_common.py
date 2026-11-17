"""Shared helpers for the commit-discipline hooks.

Every hook reads one JSON object from stdin and either stays silent (allow) or prints a
PreToolUse deny decision on stdout. All hooks fail open on input they cannot parse: a guard
that crashes on odd input should not take the whole session down with it.

Environment:
  CLAUDE_PROJECT_DIR            project root (set by Claude Code for hooks)
  COMMIT_DISCIPLINE_STATE_DIR   override for the state directory (tests use this)
  CLAUDE_PLUGIN_DATA            plugin data dir (set by Claude Code); state lives below it

Since 0.1.2 both commit guards share one reading of a shell command (git_calls below): a small
lexer that splits the command into segments, follows `cd` and `git -C` per segment, looks
through wrappers (`VAR=x git`, `then git`, `command git`) and reads script text that is fed to
a shell (`bash <<EOF`, `sh -c '...'`, `powershell -Command`, `eval`) as commands. Before 0.1.2
each guard had its own regex, and the two disagreed on what a git call is.
"""

import base64
import hashlib
import json
import os
import re
import sys

WINDOWS = os.sep == '\\'
UNKNOWN = object()          # a directory we cannot know from the text ($VAR, cd -)

SHELLS = {'bash', 'sh', 'zsh', 'dash', 'ksh', 'ash', 'busybox', 'pwsh', 'powershell', 'cmd'}
PS_SHELLS = {'pwsh', 'powershell'}
CD_WORDS = {'cd', 'chdir', 'pushd', 'set-location', 'sl', 'push-location'}
# Words that run the command after them: `then git ...`, `command git ...`.
WRAPPERS = {'sudo', 'command', 'builtin', 'exec', 'nohup', 'time', 'nice', 'env', 'xargs',
            'doas', '!', 'then', 'do', 'else', 'elif', 'if', 'while', 'until', '&', 'call'}
EVAL_WORDS = {'eval', 'iex', 'invoke-expression'}
ASSIGN = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')


def read_input():
    """Return the hook input as a dict, or None when stdin is not usable JSON."""
    try:
        raw = sys.stdin.buffer.read().decode('utf-8-sig')
        data = json.loads(raw)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def deny(reason):
    """Print a PreToolUse deny decision and stop."""
    out = {'hookSpecificOutput': {'hookEventName': 'PreToolUse',
                                  'permissionDecision': 'deny',
                                  'permissionDecisionReason': reason}}
    sys.stdout.write(json.dumps(out))
    sys.stdout.flush()
    sys.exit(0)


# ---------------------------------------------------------------------------------------------
# Paths

def _native(p):
    """Rewrite spellings that name the same place: Git Bash /c/x, \\\\?\\C:\\x, \\\\localhost\\C$\\x."""
    if not WINDOWS:
        return p
    m = re.match(r'^/(?:cygdrive/)?([A-Za-z])(?=/|$)(.*)$', p)
    if m:
        p = m.group(1) + ':' + (m.group(2) or '/')
    p = p.replace('/', '\\')
    m = re.match(r'^\\\\[?.]\\UNC\\(.*)$', p, re.I)
    if m:
        p = '\\\\' + m.group(1)
    m = re.match(r'^\\\\[?.]\\([A-Za-z]:.*)$', p)
    if m:
        p = m.group(1)
    hosts = {'localhost', '127.0.0.1', '::1', '[::1]', '.',
             (os.environ.get('COMPUTERNAME') or '').lower()} - {''}
    m = re.match(r'^\\\\([^\\]+)\\([A-Za-z])\$(\\.*)?$', p)
    if m and m.group(1).lower() in hosts:
        p = m.group(2) + ':' + (m.group(3) or '\\')
    return p


def norm(path, base=None):
    """Canonical form of a path: absolute, the same spelling for the same place, case-folded on
    Windows. 8.3 names and junctions are resolved (realpath); None for an empty path."""
    if not path:
        return None
    try:
        p = _native(os.path.expanduser(str(path)))
        if not os.path.isabs(p) or (WINDOWS and re.match(r'^\\(?!\\)', p)):
            if WINDOWS and re.match(r'^\\(?!\\)', p):    # \x on Windows: root of base's drive
                drive = os.path.splitdrive(base or os.getcwd())[0]
                p = drive + p
            else:
                p = os.path.join(base or os.getcwd(), p)
        p = os.path.normpath(os.path.abspath(p))
        try:
            r = os.path.realpath(p)
            if os.path.isabs(r) and not r.startswith('\\\\?\\'):
                p = r
        except Exception:
            pass
        return os.path.normcase(p)
    except Exception:
        return None


def is_within(path, root):
    """True when path is root itself or lies below it (both already normalised)."""
    if not path or not root:
        return False
    root = root.rstrip('\\/')
    return path == root or path.startswith(root + os.sep)


def is_within_fs(path, root):
    """is_within, and also True when an existing ancestor of path IS root on disk (samefile).

    Catches spellings that text comparison misses (an alias share, a hard-linked folder).
    """
    if is_within(norm(path), norm(root)):
        return True
    try:
        if not os.path.isdir(root):
            return False
        cur = os.path.abspath(_native(os.path.expanduser(str(path))))
        for _ in range(64):
            if os.path.exists(cur) and os.path.samefile(cur, root):
                return True
            nxt = os.path.dirname(cur)
            if nxt == cur:
                break
            cur = nxt
    except Exception:
        pass
    return False


def project_dir(data=None):
    """The project the guards protect: CLAUDE_PROJECT_DIR, else the hook cwd, else cwd."""
    for cand in (os.environ.get('CLAUDE_PROJECT_DIR'),
                 (data or {}).get('cwd'),
                 os.getcwd()):
        p = norm(cand)
        if p:
            return p
    return None


def state_dir():
    """Where the guards keep their evidence. Outside the project by default."""
    override = os.environ.get('COMMIT_DISCIPLINE_STATE_DIR')
    if override:
        return norm(override)
    data = os.environ.get('CLAUDE_PLUGIN_DATA')
    if data:
        return norm(os.path.join(data, 'state'))
    return norm(os.path.join('~', '.claude', 'commit-discipline', 'state'))


def sha256(path):
    """Hex sha256 of a file's content, or '-' when there is no such file."""
    if not path or not os.path.isfile(path):
        return '-'
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------------------------
# Lexer: command text -> events ('seg', [tokens]) / ('open',) / ('close',)
# A token is (text, quoted). Quoted text is one token and never an operator.

class _Lexer:
    def __init__(self, text, shell):
        self.t = text
        self.n = len(text)
        self.i = 0
        self.shell = shell                  # 'bash', 'ps' or 'cmd'
        self.esc = {'bash': '\\', 'ps': '`'}.get(shell)
        self.events = []
        self.seg = []
        self.word = None                    # [chars, quoted]
        self.drop_next = False              # next word is a redirect target
        self.heredocs = []                  # pending (delimiter, segment tokens at <<)
        self.depth = 0

    # -- word handling
    def _add(self, s, quoted=False):
        if self.word is None:
            self.word = ['', False]
        self.word[0] += s
        self.word[1] = self.word[1] or quoted

    def _end_word(self):
        if self.word is not None:
            if self.drop_next:
                self.drop_next = False
            else:
                self.seg.append((self.word[0], self.word[1]))
            self.word = None

    def _end_seg(self):
        self._end_word()
        if self.seg:
            self.events.append(('seg', self.seg))
        self.seg = []

    def _sub(self, text, shell=None):
        """Lex text (a $(...) body, a heredoc fed to a shell) as a nested block."""
        self._end_seg()
        self.events.append(('open',))
        self.events.extend(lex(text, shell or self.shell))
        self.events.append(('close',))

    # -- scanning helpers
    def _match_paren(self, j):
        """Index of the ')' closing a '(' just before j, respecting quotes; n if none."""
        depth, q = 1, None
        while j < self.n:
            c = self.t[j]
            if q:
                if c == q:
                    q = None
                elif c == self.esc and q == '"' and j + 1 < self.n:
                    j += 1
            elif c in '\'"':
                q = c
            elif c == self.esc and j + 1 < self.n:
                j += 1
            elif c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    return j
            j += 1
        return self.n

    def _double(self):
        """Read a "..." string; $(...) inside it runs, so it is lexed as a block."""
        self.i += 1
        buf = ''
        while self.i < self.n:
            c = self.t[self.i]
            if c == '"':
                self.i += 1
                break
            if c == self.esc and self.i + 1 < self.n:
                buf += self.t[self.i + 1]
                self.i += 2
                continue
            if c == '$' and self.t[self.i + 1:self.i + 2] == '(':
                end = self._match_paren(self.i + 2)
                inner = self.t[self.i + 2:end]
                saved, self.word = self.word, None
                saved_seg, self.seg = self.seg, []
                self.events.append(('open',))
                self.events.extend(lex(inner, self.shell))
                self.events.append(('close',))
                self.seg, self.word = saved_seg, saved
                buf += 'SUBST'
                self.i = end + 1
                continue
            if c == '`' and self.shell == 'bash':
                end = self.t.find('`', self.i + 1)
                end = self.n if end < 0 else end
                saved, self.word = self.word, None
                saved_seg, self.seg = self.seg, []
                self.events.append(('open',))
                self.events.extend(lex(self.t[self.i + 1:end], self.shell))
                self.events.append(('close',))
                self.seg, self.word = saved_seg, saved
                buf += 'SUBST'
                self.i = end + 1
                continue
            buf += c
            self.i += 1
        self._add(buf, True)

    def _heredoc_bodies(self):
        """At a newline: consume the bodies of pending heredocs."""
        for delim, seg_tokens in self.heredocs:
            lines = []
            while self.i < self.n:
                end = self.t.find('\n', self.i)
                end = self.n if end < 0 else end
                line = self.t[self.i:end].rstrip('\r')
                self.i = end + 1
                if line.strip() == delim:
                    break
                lines.append(line)
            body = '\n'.join(lines)
            word = command_word(seg_tokens)
            if word in SHELLS:
                # Script text fed to a shell is a command, not documentation.
                self._sub(body, 'ps' if word in PS_SHELLS else 'bash')
        self.heredocs = []

    def run(self):
        t, n = self.t, self.n
        while self.i < n:
            c = t[self.i]
            nxt = t[self.i + 1] if self.i + 1 < n else ''
            if self.esc and c == self.esc:
                if nxt == '\n':                       # line continuation
                    self.i += 2
                    continue
                # A bash backslash before an ordinary character is read as a path separator,
                # not dropped: C:\Program Files\Git\git.exe must stay recognisable as git.
                if nxt and (self.shell != 'bash' or nxt in ' \t;&|<>()$`"\'\\#{}*?['):
                    self._add(nxt)
                    self.i += 2
                    continue
            if c == "'":
                if self.shell == 'ps' and t[self.i - 1:self.i] == '@':
                    end = t.find("\n'@", self.i)
                    end = n if end < 0 else end
                    self.word = None if self.word and self.word[0] == '@' else self.word
                    self._add(t[self.i + 1:end], True)
                    self.i = end + 3
                    continue
                end = t.find("'", self.i + 1)
                end = n if end < 0 else end
                self._add(t[self.i + 1:end], True)
                self.i = end + 1
                continue
            if c == '"':
                if self.shell == 'ps' and t[self.i - 1:self.i] == '@':
                    end = t.find('\n"@', self.i)
                    end = n if end < 0 else end
                    self.word = None if self.word and self.word[0] == '@' else self.word
                    self._add(t[self.i + 1:end], True)
                    self.i = end + 3
                    continue
                self._double()
                continue
            if c == '#' and self.word is None:
                end = t.find('\n', self.i)
                self.i = n if end < 0 else end
                continue
            if c == '\n':
                self._end_seg()
                self.i += 1
                if self.heredocs:
                    self._heredoc_bodies()
                continue
            if c in ' \t\r':
                self._end_word()
                self.i += 1
                continue
            if c == '<' and nxt == '<' and t[self.i + 2:self.i + 3] != '<':
                self._end_word()
                m = re.match(r'<<-?\s*([\'"]?)([^\s\'";&|<>()]+)\1', t[self.i:])
                if m:
                    self.heredocs.append((m.group(2), list(self.seg)))
                    self.i += m.end()
                    continue
                self.i += 2
                continue
            if c in '<>':
                # A redirect: drop a pending fd number, skip the operator, drop its target.
                if self.word is not None and self.word[0].isdigit() and not self.word[1]:
                    self.word = None
                self._end_word()
                m = re.match(r'(?:<<<|>>|>\||>|<)&?(?:[0-9]+-?|-)?', t[self.i:])
                self.i += m.end() if m else 1
                if not (m and re.search(r'&[0-9-]', m.group(0))):
                    self.drop_next = True
                continue
            if c == '&' and nxt == '>':
                self._end_word()
                self.i += 3 if t[self.i + 2:self.i + 3] == '>' else 2
                self.drop_next = True
                continue
            if c == '$' and nxt == '(':
                end = self._match_paren(self.i + 2)
                self._sub(t[self.i + 2:end])
                self.i = end + 1
                continue
            if c == '$' and nxt == '{' and self.shell == 'bash':
                end = t.find('}', self.i)
                end = n if end < 0 else end
                self._add(t[self.i:end + 1])
                self.i = end + 1
                continue
            if c == '`' and self.shell == 'bash':
                end = t.find('`', self.i + 1)
                end = n if end < 0 else end
                self._sub(t[self.i + 1:end])
                self.i = end + 1
                continue
            if c in '(){}':
                self._end_seg()
                self.events.append(('open',) if c in '({' else ('close',))
                self.i += 1
                continue
            if c in ';|&':
                self._end_seg()
                if c == '&' and nxt != '&':
                    self.events.append(('seg', [('&', False)]))   # PowerShell call operator
                self.i += 2 if nxt == c else 1
                continue
            self._add(c)
            self.i += 1
        self._end_seg()
        return self.events


def lex(text, shell='bash'):
    try:
        return _Lexer(text, shell).run()
    except RecursionError:
        return []


def _base(word):
    w = re.split(r'[\\/]', word)[-1].lower()
    return w[:-4] if w.endswith('.exe') else w


def command_word(tokens):
    """The command a segment runs, after env assignments and wrapper words; '' when none."""
    i = 0
    while i < len(tokens):
        text, quoted = tokens[i]
        low = text.lower()
        if not quoted and ASSIGN.match(text):
            i += 1
            continue
        if not quoted and low in WRAPPERS:
            i += 1
            while i < len(tokens) and tokens[i][0].startswith('-') and low in ('sudo', 'env',
                                                                             'xargs', 'nice'):
                i += 1
            continue
        return _base(text)
    return ''


def _strip_wrappers(tokens):
    """(env assignments, remaining tokens) after the wrapper words at the start of a segment."""
    env, i = {}, 0
    while i < len(tokens):
        text, quoted = tokens[i]
        low = text.lower()
        if not quoted and ASSIGN.match(text):
            k, v = text.split('=', 1)
            env[k] = v
            i += 1
            continue
        if not quoted and low in WRAPPERS:
            i += 1
            while i < len(tokens) and tokens[i][0].startswith('-') and low in ('sudo', 'env',
                                                                             'xargs', 'nice'):
                i += 2 if tokens[i][0] in ('-u', '-g', '-n') else 1
            continue
        break
    return env, tokens[i:]


def _shell_text(words):
    """For `bash -c X`, `powershell -Command X`, `eval X`: (shell, script text) or None."""
    word = _base(words[0][0])
    rest = words[1:]
    if word in EVAL_WORDS:
        return None, ' '.join(t for t, _ in rest)
    if word in PS_SHELLS:
        k = 0
        while k < len(rest):
            text = rest[k][0]
            low = text.lower()
            if not low.startswith(('-', '/')):
                # The first positional argument is the command text.
                return 'ps', ' '.join(t for t, _ in rest[k:])
            opt = low[1:]
            if opt in ('e', 'ec') or (len(opt) >= 2 and 'encodedcommand'.startswith(opt)):
                if k + 1 < len(rest):
                    try:
                        return 'ps', base64.b64decode(rest[k + 1][0]).decode('utf-16-le')
                    except Exception:
                        return 'ps', ''
                return None
            if opt and 'command'.startswith(opt):
                return 'ps', ' '.join(t for t, _ in rest[k + 1:])
            if opt and 'file'.startswith(opt):
                return None                         # a script file: not readable as text
            if opt and any(o.startswith(opt) for o in (
                    'executionpolicy', 'windowstyle', 'version', 'configurationname',
                    'workingdirectory', 'inputformat', 'outputformat', 'settingsfile')) \
                    and len(opt) >= 2:
                k += 2
                continue
            k += 1
        return None
    if word == 'cmd':
        for k, (text, _) in enumerate(rest):
            if text.lower() in ('/c', '/k'):
                return 'cmd', ' '.join(t for t, _ in rest[k + 1:])
        return None
    if word in SHELLS:
        for k, (text, _) in enumerate(rest):
            if re.match(r'^-[a-zA-Z]*c[a-zA-Z]*$', text) and k + 1 < len(rest):
                return 'bash', rest[k + 1][0]
            if not text.startswith('-'):
                return None
    return None


def _resolve_all(dirs, target):
    out = set()
    for d in dirs:
        if d is UNKNOWN and not _is_abs(target):
            out.add(UNKNOWN)
        else:
            out.add(norm(target, base=None if d is UNKNOWN else d))
    return out


def _is_abs(p):
    return bool(re.match(r'^(?:[A-Za-z]:[\\/]|[\\/]|~)', p))


def _literal(text):
    """False for text whose value is only known at run time ($VAR, %VAR%, globs)."""
    return not re.search(r'[$%*?`]', text)


class GitCall:
    def __init__(self, sub, args, dirs, in_project, base):
        self.sub = sub              # subcommand as written, lower-cased
        self.args = args            # tokens after the subcommand
        self.dirs = dirs            # possible working directories (UNKNOWN allowed)
        self.in_project = in_project
        self.base = base            # directory to resolve relative paths against

    def text(self):
        return ('git %s %s' % (self.sub, ' '.join(t for t, _ in self.args))).strip()


def git_calls(cmd, project, cwd=None, shell='bash'):
    """Every git call in a shell command, with whether it can act on the project.

    A call counts as outside the project only when EVERY directory it can run in lies outside
    the project: a cd inside ( ) or { } is merged with the directory before the block instead
    of replacing it, a cd to a directory that does not exist is ignored (it fails), and a
    target known only at run time counts as possibly inside.
    """
    start = cwd if cwd and is_within(cwd, project) else project
    calls = []
    state = {'dirs': {start}, 'env': {}}
    stack = []

    def walk(events, sh):
        for ev in events:
            if ev[0] == 'open':
                stack.append(set(state['dirs']))
                continue
            if ev[0] == 'close':
                if stack:
                    state['dirs'] = stack.pop() | state['dirs']
                continue
            segment(ev[1], sh)

    def segment(tokens, sh):
        env, words = _strip_wrappers(tokens)
        if not words:
            # `export GIT_DIR=x`-style persistence is handled below; a bare assignment in
            # bash persists for the rest of the command too.
            for k, v in env.items():
                state['env'][k] = v
            return
        word = _base(words[0][0])
        if word in ('export', 'set', 'set-item', 'setx'):
            for t, _ in words[1:]:
                if ASSIGN.match(t):
                    k, v = t.split('=', 1)
                    state['env'][k] = v
            return
        m = re.match(r'^\$env:([A-Za-z_][A-Za-z0-9_]*)$', words[0][0], re.I)
        if m and len(words) >= 3 and words[1][0] == '=':
            state['env'][m.group(1).upper()] = words[2][0]
            return
        m = re.match(r'^\$env:([A-Za-z_][A-Za-z0-9_]*)=(.*)$', words[0][0], re.I)
        if m:
            state['env'][m.group(1).upper()] = m.group(2) or (words[1][0] if len(words) > 1 else '')
            return
        if word in CD_WORDS:
            args = [t for t, _ in words[1:]
                    if not re.match(r'^-(?:P|L|e|@|Path|LiteralPath|PassThru)$', t, re.I)]
            if not args or args[0] == '-' or not _literal(args[0]):
                state['dirs'] = {UNKNOWN} if not args or args[0] == '-' else \
                    state['dirs'] | {UNKNOWN}
                return
            new = _resolve_all(state['dirs'], args[0])
            known = {d for d in new if d is not UNKNOWN}
            if known and all(os.path.isdir(d) for d in known):
                state['dirs'] = new
            return
        if word in ('popd', 'pop-location'):
            state['dirs'] = state['dirs'] | {UNKNOWN}
            return
        st = _shell_text(words)
        if st is not None:
            sub_shell, script = st
            stack.append(set(state['dirs']))
            walk(lex(script, sub_shell or sh), sub_shell or sh)
            state['dirs'] = stack.pop() | state['dirs']
            return
        if word != 'git':
            return
        git_call(env, words[1:])

    def git_call(env, rest):
        dirs = set(state['dirs'])
        allenv = dict(state['env'])
        allenv.update(env)
        git_dir = allenv.get('GIT_DIR')
        work_tree = allenv.get('GIT_WORK_TREE')
        i = 0
        while i < len(rest):
            t = rest[i][0]
            if t == '-C' and i + 1 < len(rest):
                target = rest[i + 1][0]
                dirs = _resolve_all(dirs, target) if _literal(target) else dirs | {UNKNOWN}
                i += 2
                continue
            if t == '-c' and i + 1 < len(rest):
                i += 2
                continue
            m = re.match(r'^--(git-dir|work-tree|namespace|super-prefix|config-env|exec-path)'
                         r'(?:=(.*))?$', t)
            if m:
                val = m.group(2)
                if val is None and m.group(1) != 'exec-path' and i + 1 < len(rest):
                    val = rest[i + 1][0]
                    i += 1
                if m.group(1) == 'git-dir':
                    git_dir = val
                elif m.group(1) == 'work-tree':
                    work_tree = val
                i += 1
                continue
            if t.startswith('-'):
                i += 1
                continue
            break
        if i >= len(rest):
            return
        sub = rest[i][0].lower()
        args = rest[i + 1:]

        def where(spec):
            if not spec or not _literal(spec):
                return {UNKNOWN}
            return _resolve_all(dirs, spec)

        repo = where(git_dir) if git_dir is not None else (
            where(work_tree) if work_tree is not None else dirs)
        inside = any(d is UNKNOWN or is_within(d, project) for d in repo)
        known = [d for d in dirs if d is not UNKNOWN and is_within(d, project)]
        base = known[0] if known else start
        calls.append(GitCall(sub, args, dirs, inside, base))

    walk(lex(cmd, shell), shell)
    return calls


def shell_of(data):
    return 'ps' if (data or {}).get('tool_name') == 'PowerShell' else 'bash'


# ---------------------------------------------------------------------------------------------
# Reading git arguments

COMMIT_VALUE_SHORT = set('mFCctS')
COMMIT_VALUE_LONG = ('message', 'file', 'author', 'date', 'reuse-message', 'reedit-message',
                     'fixup', 'squash', 'template', 'cleanup', 'trailer', 'pathspec-from-file')


def split_args(args, value_short=frozenset(), value_long=()):
    """Split git arguments into (options, paths, has_dashdash). Values of options that take one
    are skipped, so a message is never read as an option or a path."""
    opts, paths, dd = [], [], False
    i = 0
    while i < len(args):
        t, q = args[i]
        if dd:
            paths.append((t, q))
        elif t == '--' and not q:
            dd = True
        elif t.startswith('--') and not q:
            name = t[2:].split('=', 1)[0]
            opts.append(t)
            if '=' not in t and any(v.startswith(name) for v in value_long) and len(name) >= 2 \
                    and i + 1 < len(args):
                i += 1
        elif t.startswith('-') and len(t) > 1 and not q:
            opts.append(t)
            for k, ch in enumerate(t[1:]):
                if ch in value_short:
                    if k == len(t) - 2 and i + 1 < len(args):
                        i += 1
                    break
        else:
            paths.append((t, q))
        i += 1
    return opts, paths, dd


def long_is(opt, *names):
    """True when --opt (possibly abbreviated, as git allows) can mean one of names."""
    if not opt.startswith('--'):
        return False
    name = opt[2:].split('=', 1)[0]
    return bool(name) and any(n.startswith(name) for n in names)


def short_has(opt, letters, value_short=frozenset()):
    """True when a short-option cluster like -vA carries one of letters before a value."""
    if not opt.startswith('-') or opt.startswith('--'):
        return False
    for ch in opt[1:]:
        if ch in letters:
            return True
        if ch in value_short:
            return False
    return False


def whole_tree(token, base, project):
    """True for a pathspec that can take everything: pathspec magic (:/, :(top)), a glob, or a
    path that is the project root or above it."""
    if token.startswith(':'):
        return True
    if re.search(r'[*?\[]', token):
        return True
    full = norm(token, base=base)
    return bool(full) and is_within(project, full)
