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
import difflib
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
    except RecursionError:
        return TOO_DEEP
    except Exception:
        return None
    return data if isinstance(data, dict) else None


# Input nested deeper than json can read. Not something Claude Code sends by itself, but a
# model can pass it in a free-form tool argument; a guard that cannot read it refuses it.
TOO_DEEP = {'__too_deep__': True}


def deny_too_deep():
    deny('commit-discipline: the tool input is nested too deeply to check, so it is refused.')


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
        # A hard link to a file in root is the same file under another name.
        if os.path.isfile(path) and os.path.isdir(root):
            for name in os.listdir(root):
                f = os.path.join(root, name)
                if os.path.isfile(f) and os.path.samefile(path, f):
                    return True
    except Exception:
        pass
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
# Lexer: command text -> events
#   ('seg', tokens, info)   one simple command. tokens are (text, quoted) pairs; info holds
#                           'redirs' (redirect targets), 'stdin' (heredoc or here-string text)
#                           and 'piped' (its stdin comes from the previous command through |).
#   ('open',) / ('close',)  a block: ( ), { }, $( ), backticks, process substitution.
# Text whose value only exists at run time ($VAR, $(...)) keeps a '$' so _literal() sees it.

SUBST = '$(SUBST)'


class _Lexer:
    def __init__(self, text, shell):
        self.t, self.n, self.i = text, len(text), 0
        self.shell = shell                  # 'bash', 'ps' or 'cmd'
        self.esc = {'bash': '\\', 'ps': '`'}.get(shell)
        self.events = []
        self.seg, self.info = [], self._new_info()
        self.parts, self.quoted = None, False   # the current word, as a list of parts
        self.target = None                  # the next word is a 'redir' target or 'stdin'
        self.heredocs = []                  # pending (delimiter, literal, info)

    @staticmethod
    def _new_info(piped=False):
        return {'redirs': [], 'stdin': None, 'piped': piped}

    # -- words and segments
    def _add(self, s, quoted=False):
        if self.parts is None:
            self.parts, self.quoted = [], False
        self.parts.append(s)
        self.quoted = self.quoted or quoted

    def _end_word(self):
        if self.parts is None:
            return
        word = ''.join(self.parts)
        if self.target == 'redir':
            self.info['redirs'].append(word)
        elif self.target == 'stdin':
            self.info['stdin'] = word
        else:
            self.seg.append((word, self.quoted))
        self.parts, self.target = None, None

    def _end_seg(self, piped_next=False):
        self._end_word()
        self.target = None
        if self.seg or self.info['redirs'] or self.info['stdin'] is not None:
            self.events.append(('seg', self.seg, self.info))
        self.seg, self.info = [], self._new_info(piped_next)

    def _block(self, text, shell=None):
        """Text that runs on its own ($( ), backticks, <( )) as a block. The current command
        is not ended: the block's output only becomes part of a word."""
        self.events.append(('open',))
        self.events.extend(lex(text, shell or self.shell))
        self.events.append(('close',))

    # -- scanning helpers
    def _match_paren(self, j, text=None):
        """Index of the ')' closing a '(' just before j, respecting quotes; len if none."""
        t = self.t if text is None else text
        n = len(t)
        depth, q = 1, None
        while j < n:
            c = t[j]
            if q:
                if c == q:
                    q = None
                elif c == self.esc and q == '"' and j + 1 < n:
                    j += 1
            elif c in '\'"':
                q = c
            elif c == self.esc and j + 1 < n:
                j += 1
            elif c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    return j
            j += 1
        return n

    def _subst_at(self, j):
        end = self._match_paren(j + 2)
        self._block(self.t[j + 2:end])
        return end + 1

    def _backtick_at(self, j):
        end = self.t.find('`', j + 1)
        end = self.n if end < 0 else end
        self._block(self.t[j + 1:end])
        return end + 1

    def _expanding(self, text):
        """Text that expands like a "..." string (an unquoted heredoc, a @"..."@ here-string):
        every $( ) and backtick in it runs, so each is lexed as a block."""
        j, n = 0, len(text)
        while j < n:
            c = text[j]
            if c == self.esc and j + 1 < n:
                j += 2
                continue
            if c == '$' and text[j + 1:j + 2] == '(':
                end = self._match_paren(j + 2, text)
                self._block(text[j + 2:end])
                j = end + 1
                continue
            if c == '`' and self.shell == 'bash':
                end = text.find('`', j + 1)
                end = n if end < 0 else end
                self._block(text[j + 1:end])
                j = end + 1
                continue
            j += 1

    def _double(self):
        """A "..." string. In bash a backslash only escapes $ ` " \\ and a newline; $( ) and
        backticks inside run."""
        self.i += 1
        buf = []
        while self.i < self.n:
            c = self.t[self.i]
            if c == '"':
                self.i += 1
                break
            if c == self.esc and self.i + 1 < self.n:
                nxt = self.t[self.i + 1]
                if self.shell != 'bash' or nxt in '$`"\\\n':
                    if nxt != '\n':
                        buf.append(nxt)
                else:
                    buf.append(c + nxt)         # C:\AI stays C:\AI
                self.i += 2
                continue
            if c == '$' and self.t[self.i + 1:self.i + 2] == '(':
                self.i = self._subst_at(self.i)
                buf.append(SUBST)
                continue
            if c == '`' and self.shell == 'bash':
                self.i = self._backtick_at(self.i)
                buf.append(SUBST)
                continue
            buf.append(c)
            self.i += 1
        self._add(''.join(buf), True)

    def _here_string(self, quote):
        """PowerShell @'...'@ (literal) or @"..."@ (expanding), the @ already in the word."""
        if self.parts and self.parts[-1] == '@':
            self.parts.pop()
        end = self.t.find('\n' + quote + '@', self.i)
        end = self.n if end < 0 else end
        body = self.t[self.i + 1:end]
        if quote == '"':
            self._expanding(body)
        self._add(body, True)
        self.i = end + 3

    def _heredoc_bodies(self):
        """At a newline: the bodies of pending heredocs become their command's stdin."""
        for delim, literal, info in self.heredocs:
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
            if not literal and self.shell == 'bash':
                self._expanding(body)
            info['stdin'] = body
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
                if nxt and (self.shell != 'bash' or nxt in ' \t;&|<>()$`"\'\\#{}*?[~!'):
                    self._add(nxt)
                    self.i += 2
                    continue
            if c == '$' and nxt == "'" and self.shell == 'bash':     # $'...' (ANSI-C)
                end = t.find("'", self.i + 2)
                end = n if end < 0 else end
                self._add(t[self.i + 2:end], True)
                self.i = end + 1
                continue
            if c == "'":
                if self.shell == 'ps' and self.parts and self.parts[-1] == '@':
                    self._here_string("'")
                    continue
                end = t.find("'", self.i + 1)
                end = n if end < 0 else end
                self._add(t[self.i + 1:end], True)
                self.i = end + 1
                continue
            if c == '"':
                if self.shell == 'ps' and self.parts and self.parts[-1] == '@':
                    self._here_string('"')
                    continue
                self._double()
                continue
            if c == '<' and nxt == '#' and self.shell == 'ps':           # <# block comment #>
                end = t.find('#>', self.i + 2)
                self.i = n if end < 0 else end + 2
                continue
            if c == '#' and self.parts is None:
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
            if c in '<>' and nxt == '(' and self.shell == 'bash':        # <( ) and >( )
                end = self._match_paren(self.i + 2)
                self._block(t[self.i + 2:end])
                self._add(SUBST)
                self.i = end + 1
                continue
            if c == '<' and nxt == '<' and t[self.i + 2:self.i + 3] == '<':   # <<< here-string
                self._end_word()
                self.i += 3
                self.target = 'stdin'
                continue
            if c == '<' and nxt == '<':
                self._end_word()
                m = re.match(r'<<-?\s*([\'"]?)([^\s\'";&|<>()]+)\1', t[self.i:])
                if m:
                    self.heredocs.append((m.group(2), bool(m.group(1)), self.info))
                    self.i += m.end()
                    continue
                self.i += 2
                continue
            if c in '<>':
                # A redirect: drop a pending fd number, skip the operator, keep its target.
                if self.parts is not None and not self.quoted and ''.join(self.parts).isdigit():
                    self.parts = None
                self._end_word()
                m = re.match(r'(?:>>|>\||>|<)&?(?:[0-9]+-?|-)?', t[self.i:])
                self.i += m.end() if m else 1
                if not (m and re.search(r'&[0-9-]', m.group(0))):
                    self.target = 'redir'
                continue
            if c == '&' and nxt == '>':
                self._end_word()
                self.i += 3 if t[self.i + 2:self.i + 3] == '>' else 2
                self.target = 'redir'
                continue
            if c == '$' and nxt == '(':
                self.i = self._subst_at(self.i)
                self._add(SUBST)
                continue
            if c == '$' and nxt == '{' and self.shell == 'bash':
                end = t.find('}', self.i)
                end = n if end < 0 else end
                self._add(t[self.i:end + 1])
                self.i = end + 1
                continue
            if c == '`' and self.shell == 'bash':
                self.i = self._backtick_at(self.i)
                self._add(SUBST)
                continue
            if c in '{}' and self.shell == 'bash':
                # In bash { and } are reserved words only as a word of their own: {} in
                # `xargs -I{} git add {}` and {.,} in a brace expansion are text.
                own = self.parts is None and (nxt == '' or nxt in ' \t\r\n' +
                                              (';&|)' if c == '}' else ''))
                if not own:
                    self._add(c)
                    self.i += 1
                    continue
            if c in '(){}':
                self._end_seg()
                self.events.append(('open',) if c in '({' else ('close',))
                self.i += 1
                continue
            if c in ';|&':
                self._end_seg(piped_next=(c == '|' and nxt != '|'))
                self.i += 2 if nxt == c else 1
                continue
            self._add(c)
            self.i += 1
        self._end_seg()
        if self.heredocs:
            self._heredoc_bodies()
        return self.events


class TooComplex(Exception):
    """The command nests deeper than the lexer can follow. The guards refuse such a command
    when it mentions git: what cannot be read does not go through."""


def lex(text, shell='bash'):
    try:
        return _Lexer(text, shell).run()
    except RecursionError:
        raise TooComplex()


def mentions_git(cmd):
    """True when the command text names git, also when split by quotes (g''it)."""
    return bool(re.search(r'(?i)git', re.sub(r'[\'"`\\^]', '', cmd or '')))


def _base(word):
    w = re.split(r'[\\/]', word)[-1].lower()
    return w[:-4] if w.endswith('.exe') else w


# Wrapper words that run the command after them, with the options of theirs that take a
# value, and how many positional arguments of their own come before the command.
WRAPPER_OPTS = {
    'sudo': ({'-u', '-g', '-h', '-p', '-C', '-r', '-t', '-U', '-D'}, 0),
    'doas': ({'-u', '-C'}, 0),
    'env': ({'-u', '-C', '-S', '--unset', '--chdir', '--split-string'}, 0),
    'xargs': ({'-I', '-n', '-L', '-P', '-d', '-E', '-s', '-a', '--max-args', '--max-procs',
               '--delimiter', '--arg-file', '--replace'}, 0),
    'nice': ({'-n', '--adjustment'}, 0),
    'ionice': ({'-c', '-n', '-p', '-t'}, 0),
    'timeout': ({'-s', '-k', '--signal', '--kill-after'}, 1),
    'taskset': (set(), 1),
    'chrt': (set(), 1),
    'stdbuf': ({'-i', '-o', '-e'}, 0),
    'time': ({'-f', '-o'}, 0),
}
KEYWORDS = {'!', 'then', 'do', 'else', 'elif', 'if', 'while', 'until', '&', 'call'}
WRAPPERS = {'sudo', 'command', 'builtin', 'exec', 'nohup', 'winpty', 'unbuffer', 'chronic',
            'caffeinate'} | set(WRAPPER_OPTS) | KEYWORDS


def _strip_wrappers(tokens, via=None):
    """(env assignments, remaining tokens) after the wrapper words at the start of a segment.
    Wrapper words seen are added to the set via, when given."""
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
            if via is not None:
                via.add(low)
            i += 1
            if low in KEYWORDS:
                continue
            vals, positional = WRAPPER_OPTS.get(low, (set(), 0))
            while i < len(tokens) and tokens[i][0].startswith('-') and len(tokens[i][0]) > 1:
                opt = tokens[i][0]
                i += 1
                if opt in vals and '=' not in opt:
                    i += 1
            i += positional
            continue
        break
    return env, tokens[i:]


def command_word(tokens):
    """The command a segment runs, after env assignments and wrapper words; '' when none."""
    _, words = _strip_wrappers(tokens)
    return _base(words[0][0]) if words else ''


STDIN = object()            # _shell_text: the script comes from stdin


def _shell_text(words):
    """For `bash -c X`, `powershell -Command X`, `eval X`: (shell, script text), with STDIN
    as the text when the shell reads its script from stdin; None when it runs a script file
    or is not a shell at all."""
    word = _base(words[0][0])
    rest = words[1:]
    if word in EVAL_WORDS:
        if rest and re.match(r'^-c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$', rest[0][0], re.I):
            rest = rest[1:]
        return None, (' '.join(t for t, _ in rest) if rest else STDIN)
    if word in PS_SHELLS:
        k = 0
        while k < len(rest):
            text = rest[k][0]
            low = text.lower()
            if low == '-':
                return 'ps', STDIN
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
                tail = rest[k + 1:]
                if not tail or tail[0][0] == '-':
                    return 'ps', STDIN
                return 'ps', ' '.join(t for t, _ in tail)
            if opt and 'file'.startswith(opt):
                return None                         # a script file: not readable as text
            if opt and any(o.startswith(opt) for o in (
                    'executionpolicy', 'windowstyle', 'version', 'configurationname',
                    'workingdirectory', 'inputformat', 'outputformat', 'settingsfile')) \
                    and len(opt) >= 2:
                k += 2
                continue
            k += 1
        return 'ps', STDIN
    if word == 'cmd':
        for k, (text, _) in enumerate(rest):
            if text.lower() in ('/c', '/k'):
                return 'cmd', ' '.join(t for t, _ in rest[k + 1:])
        return 'cmd', STDIN
    if word in SHELLS:
        has_c, k = False, 0
        while k < len(rest):
            text = rest[k][0]
            if text == '--':
                k += 1
                break
            if text in ('-o', '+o', '-O', '+O', '--rcfile', '--init-file'):
                k += 2
                continue
            if text.startswith('--'):
                k += 1
                continue
            if re.match(r'^[-+][A-Za-z]+$', text):
                if text.startswith('-') and 'c' in text[1:]:
                    has_c = True
                k += 1
                continue
            break
        if k < len(rest):
            return ('bash', rest[k][0]) if has_c else None
        return None if has_c else ('bash', STDIN)
    return None


def _resolve_all(dirs, target):
    out = set()
    for d in dirs:
        if d is UNKNOWN and not _is_abs(target):
            out.add(UNKNOWN)
        else:
            full = norm(target, base=None if d is UNKNOWN else d)
            out.add(full if full else UNKNOWN)
    return out


def _is_abs(p):
    return bool(re.match(r'^(?:[A-Za-z]:[\\/]|[\\/]|~)', p))


def _literal(text):
    """False for text whose value is only known at run time ($VAR, %VAR%, globs)."""
    return not re.search(r'[$%*?`]', text)


def _start_process(words):
    """PowerShell Start-Process git -ArgumentList ...: the git arguments as tokens, or None."""
    if _base(words[0][0]) not in ('start-process', 'saps', 'start'):
        return None
    path, arglist, k = None, [], 1
    while k < len(words):
        t = words[k][0]
        low = t.lower()
        if low in ('-filepath', '-path') and k + 1 < len(words):
            path = words[k + 1][0]
            k += 2
            continue
        if low in ('-argumentlist', '-args') and k + 1 < len(words):
            # The value is the next word, also when it starts with a dash; a list goes on
            # while the words are joined by commas.
            arglist.append(words[k + 1][0])
            k += 2
            while k < len(words) and (words[k][0].startswith(',') or arglist[-1].endswith(',')):
                arglist.append(words[k][0])
                k += 1
            continue
        if not t.startswith('-') and path is None:
            path = t
        elif not t.startswith('-') and path is not None:
            arglist.append(t)
        k += 1
    if not path or _base(path) != 'git':
        return None
    out = []
    for a in arglist:
        for part in a.split(','):
            out += [(p, False) for p in part.split()]
    return out


# Commands that only read: their arguments are not files they change (S-01 of the 0.1.2
# slooppas). A redirect target always counts as changed.
READ_WORDS = {'ls', 'dir', 'cat', 'type', 'echo', 'printf', 'pwd', 'head', 'tail', 'grep',
              'egrep', 'rg', 'wc', 'less', 'more', 'diff', 'stat', 'file', 'which', 'where',
              'test', '[', 'true', 'false', 'sleep', 'start-sleep', 'get-content', 'gc',
              'get-childitem', 'gci', 'test-path', 'write-output', 'write-host',
              'select-string', 'sls', 'get-item', 'gi', 'resolve-path', 'find', 'tree',
              'sha256sum', 'md5sum', 'get-filehash', 'measure-object', 'du', 'df'}
GIT_READ_SUBS = {'add', 'stage', 'status', 'diff', 'log', 'show', 'rev-parse', 'ls-files',
                 'commit', 'blame', 'grep', 'fetch', 'branch', 'remote', 'describe', 'reflog',
                 'cat-file', 'shortlog', 'whatchanged', 'ls-tree', 'config', 'push', 'tag'}
INTERPRETERS = {'python', 'python3', 'py', 'node', 'ruby', 'perl', 'deno', 'bun', 'bash', 'sh',
                'zsh', 'pwsh', 'powershell'}
OUTPUT_WORDS = {'echo', 'printf', 'write-output', 'write-host'}
PASS_WORDS = {'cat', 'type', 'get-content', 'gc', 'tee'}


def _touched(words, info):
    """Paths a command may change: its redirect targets, and its arguments unless it only
    reads. The script an interpreter runs is not counted; what it gets as arguments is."""
    out = list(info['redirs'])
    if not words:
        return out
    word = _base(words[0][0])
    if word in READ_WORDS or word in CD_WORDS:
        return out
    args = [t for t, _ in words[1:]]
    if word == 'git':
        i = 0
        while i < len(args) and args[i].startswith('-'):
            i += 2 if args[i] in ('-C', '-c') else 1
        if i < len(args) and args[i].lower() in GIT_READ_SUBS:
            return out
    if word in INTERPRETERS:
        i = 0
        while i < len(args) and args[i].startswith('-'):
            if args[i] in ('-m', '-c', '-File', '-Command'):
                i += 1
                break
            i += 1
        args = args[i + 1:]
    return out + [a for a in args if not a.startswith('-')]


class GitCall:
    def __init__(self, sub, args, dirs, in_project, bases, hidden_args=False, touched=()):
        self.sub = sub              # subcommand as written, lower-cased
        self.args = args            # tokens after the subcommand
        self.dirs = dirs            # possible working directories (UNKNOWN allowed)
        self.in_project = in_project
        self.bases = bases          # in-project directories to resolve relative paths against
        self.base = bases[0]
        self.unknown_dir = UNKNOWN in dirs
        self.hidden_args = hidden_args  # more arguments arrive at run time (xargs, find -exec)
        self.touched = list(touched)    # paths earlier commands in the same command may change

    def text(self):
        return ('git %s %s' % (self.sub, ' '.join(t for t, _ in self.args))).strip()


def git_calls(cmd, project, cwd=None, shell='bash'):
    """Every git call in a shell command, with whether it can act on the project.

    A call counts as outside the project only when EVERY directory it can run in lies outside
    the project: a cd inside ( ) or { } is merged with the directory before the block instead
    of replacing it, a cd to a directory that does not exist is ignored (it fails), and a
    target known only at run time counts as possibly inside. The command starts in the
    hook's working directory.
    """
    start = cwd if cwd and os.path.isdir(cwd) else project
    calls = []
    state = {'dirs': {start}, 'env': {}, 'hidden': 0, 'touched': []}
    stack = []

    def walk(events, sh):
        prev_out = None
        for ev in events:
            if ev[0] == 'open':
                stack.append(set(state['dirs']))
                prev_out = None
                continue
            if ev[0] == 'close':
                if stack:
                    state['dirs'] = stack.pop() | state['dirs']
                continue
            info = ev[2]
            stdin = info['stdin']
            if stdin is None and info['piped']:
                stdin = prev_out
            prev_out = segment(ev[1], sh, stdin, info)

    def nested(script, sh, hidden=False):
        stack.append(set(state['dirs']))
        state['hidden'] += hidden
        try:
            walk(lex(script, sh), sh)
        finally:
            state['hidden'] -= hidden
            state['dirs'] = stack.pop() | state['dirs']

    def segment(tokens, sh, stdin=None, info=None):
        """Follow one simple command; return its output text when it is known."""
        info = info or _Lexer._new_info()
        via = set()
        env, words = _strip_wrappers(tokens, via)
        bases = [d for d in state['dirs'] if d is not UNKNOWN] or [start]
        for p in _touched(words, info):
            if p and _literal(p):
                state['touched'] += [norm(p, base=b) for b in bases]
        if not words:
            # A bare assignment in bash persists for the rest of the command too.
            for k, v in env.items():
                state['env'][k] = v
            return None
        word = _base(words[0][0])
        if word in ('export', 'set', 'set-item', 'setx'):
            for t, _ in words[1:]:
                if ASSIGN.match(t):
                    k, v = t.split('=', 1)
                    state['env'][k] = v
            return None
        m = re.match(r'^\$env:([A-Za-z_][A-Za-z0-9_]*)$', words[0][0], re.I)
        if m and len(words) >= 3 and words[1][0] == '=':
            state['env'][m.group(1).upper()] = words[2][0]
            return None
        m = re.match(r'^\$env:([A-Za-z_][A-Za-z0-9_]*)=(.*)$', words[0][0], re.I)
        if m:
            state['env'][m.group(1).upper()] = m.group(2) or (words[1][0] if len(words) > 1 else '')
            return None
        if word in CD_WORDS:
            args = [t for t, _ in words[1:]
                    if not re.match(r'^-(?:P|L|e|@|Path|LiteralPath|PassThru)$', t, re.I)]
            if args and args[0] == '':
                return None                         # cd "" stays where it is
            if not args or args[0] == '-' or not _literal(args[0]):
                state['dirs'] = {UNKNOWN} if not args or args[0] == '-' else \
                    state['dirs'] | {UNKNOWN}
                return None
            new = _resolve_all(state['dirs'], args[0])
            known = {d for d in new if d is not UNKNOWN}
            if known and all(os.path.isdir(d) for d in known):
                state['dirs'] = new
            return None
        if word in ('popd', 'pop-location'):
            state['dirs'] = state['dirs'] | {UNKNOWN}
            return None
        st = _shell_text(words)
        if st is not None:
            sub_shell, script = st
            if script is STDIN:
                script = stdin
            if script:
                nested(script, sub_shell or sh, 'xargs' in via)
            return None
        if word == 'find':
            for k, (t, _) in enumerate(words):
                if t in ('-exec', '-execdir', '-ok', '-okdir'):
                    sub = []
                    for t2, q2 in words[k + 1:]:
                        if t2 in (';', '+'):
                            break
                        sub.append((t2, q2))
                    if sub:
                        state['hidden'] += 1
                        try:
                            segment(sub, sh)
                        finally:
                            state['hidden'] -= 1
            return None
        started = _start_process(words)
        if started is not None:
            git_call(env, started, sh)
            return None
        if word == 'git':
            git_call(env, words[1:], sh, 'xargs' in via)
            return None
        if word in OUTPUT_WORDS:
            return ' '.join(t for t, _ in words[1:] if not re.match(r'^-[neE]+$', t))
        if word in PASS_WORDS and len(words) == 1:
            return stdin
        if all(q for _, q in tokens):
            return ' '.join(t for t, _ in tokens)       # a PowerShell string as an expression
        return None

    def git_call(env, rest, sh='bash', hidden=False):
        dirs = set(state['dirs'])
        allenv = dict(state['env'])
        allenv.update(env)
        git_dir = allenv.get('GIT_DIR')
        work_tree = allenv.get('GIT_WORK_TREE')
        aliases = {}                # git -c alias.NAME=VALUE on this call
        i = 0
        while i < len(rest):
            t = rest[i][0]
            if t == '-C' and i + 1 < len(rest):
                target = rest[i + 1][0]
                if target != '':                    # git -C "" stays where it is
                    dirs = _resolve_all(dirs, target) if _literal(target) else dirs | {UNKNOWN}
                i += 2
                continue
            if t == '-c' and i + 1 < len(rest):
                m = re.match(r'^alias\.([^=]+)=(.*)$', rest[i + 1][0], re.S)
                if m:
                    aliases[m.group(1).lower()] = m.group(2)
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
        if sub in aliases:
            value = aliases.pop(sub)
            if value.startswith('!'):
                # A shell alias: its text runs as a command, with the call's arguments after.
                nested(value[1:] + ' ' + ' '.join(t for t, _ in args), sh)
                return
            expanded = [(p, False) for p in value.split()]
            if expanded:
                sub, args = expanded[0][0].lower(), expanded[1:] + list(args)
        if sub not in ('commit', 'add', 'stage'):
            # help.autocorrect runs a near miss as the real thing (git comit -> commit).
            close = difflib.get_close_matches(sub, ['commit', 'add', 'stage'], 1, 0.8)
            if close:
                sub = close[0]

        def where(spec):
            if not spec or not _literal(spec):
                return {UNKNOWN}
            return _resolve_all(dirs, spec)

        repo = where(git_dir) if git_dir is not None else (
            where(work_tree) if work_tree is not None else dirs)
        inside = any(d is UNKNOWN or is_within(d, project) for d in repo)
        known = sorted(d for d in dirs if d is not UNKNOWN and is_within(d, project))
        calls.append(GitCall(sub, args, dirs, inside, known or [start],
                             hidden or state['hidden'] > 0, state['touched']))

    try:
        walk(lex(cmd, shell), shell)
    except RecursionError:
        raise TooComplex()
    return calls


def shell_of(data):
    return 'ps' if (data or {}).get('tool_name') == 'PowerShell' else 'bash'


# ---------------------------------------------------------------------------------------------
# Reading git arguments

COMMIT_VALUE_SHORT = set('mFCct')       # the value may be the next word
COMMIT_ATTACHED_SHORT = set('Su')       # the value, if any, is attached (-Skeyid, -uno)
COMMIT_STOP_SHORT = COMMIT_VALUE_SHORT | COMMIT_ATTACHED_SHORT
COMMIT_VALUE_LONG = ('message', 'file', 'author', 'date', 'reuse-message', 'reedit-message',
                     'fixup', 'squash', 'template', 'cleanup', 'trailer', 'pathspec-from-file')


def split_args(args, value_short=frozenset(), value_long=(), attached=frozenset()):
    """Split git arguments into (options, paths, has_dashdash). Values of options that take one
    are skipped, so a message is never read as an option or a path. Quoting does not matter:
    the shell removes it, and git sees '-A' as -A."""
    opts, paths, dd = [], [], False
    i = 0
    while i < len(args):
        t, q = args[i]
        if dd:
            paths.append((t, q))
        elif t == '--':
            dd = True
        elif t.startswith('--'):
            name = t[2:].split('=', 1)[0]
            opts.append(t)
            if '=' not in t and any(v.startswith(name) for v in value_long) and len(name) >= 2 \
                    and i + 1 < len(args):
                i += 1
        elif t.startswith('-') and len(t) > 1:
            opts.append(t)
            for k, ch in enumerate(t[1:]):
                if ch in attached:
                    break
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


def braces(token):
    """Bash brace expansion of a path ({a,b}.py -> a.py b.py), at most 64 results."""
    m = re.search(r'\{([^{}]*,[^{}]*)\}', token)
    if not m:
        return [token]
    out = []
    for alt in m.group(1).split(','):
        out += braces(token[:m.start()] + alt + token[m.end():])
        if len(out) >= 64:
            break
    return out[:64]


def whole_tree(token, bases, project):
    """True for a pathspec that can take everything: pathspec magic (:/, :(top)), a glob, or a
    path that is the project root or above it, from any of the directories git may run in."""
    if isinstance(bases, str):
        bases = [bases]
    for t in braces(token):
        if t.startswith(':') or re.search(r'[*?\[]', t):
            return True
        for b in bases:
            full = norm(t, base=b) if t else None
            if full and is_within(project, full):
                return True
    return False
