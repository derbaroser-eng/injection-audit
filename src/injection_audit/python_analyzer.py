"""Python AST analyser: taint sources -> shell/argument sinks (CWE-78/88/95)."""
import ast
import sys as _sys

from .model import Finding
from .rules import RULE_META, message_for
from .taint import dotted_name, expression_taint

SUBPROCESS_SINKS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output", "subprocess.Popen", "subprocess.getoutput",
    "subprocess.getstatusoutput",
}
EXEC_SINKS = {
    "os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execv",
    "os.execve", "os.execvp", "os.execvpe", "os.spawnl", "os.spawnle",
    "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp",
    "os.spawnvpe", "os.posix_spawn", "os.posix_spawnp",
}
EVAL_SINKS = {"eval", "exec", "builtins.eval", "builtins.exec"}

_FLOW_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)

_SHELL_PROGRAMS = {"sh", "bash", "dash", "zsh", "ksh", "ash", "csh", "tcsh"}


def _literal_str(node):
    """Return the value of a plain string literal, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _shell_argv(elts):
    """Return (is_shell, command_index) for a list-form argv.

    is_shell is True when argv[0] names a known shell interpreter.
    command_index is the position following a -c style flag, i.e. the
    element that the shell re-parses as command syntax.
    """
    if not elts:
        return False, None
    program = _literal_str(elts[0])
    if program is None:
        return False, None
    program = program.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if program not in _SHELL_PROGRAMS:
        return False, None
    index = None
    for position, element in enumerate(elts[1:], 1):
        flag = _literal_str(element)
        if flag and flag.startswith("-") and "c" in flag[1:]:
            index = position + 1
            break
    if index is None or index >= len(elts):
        return True, None
    return True, index


def _merge_envs(base, *others):
    out = dict(base)
    for env in others:
        for key, value in env.items():
            if key not in out:
                out[key] = value
    return out


class PythonAnalyzer:
    def __init__(self, source, filename, platform=None):
        self.src = source
        self.filename = filename
        self.lines = source.splitlines()
        self.platform = str(platform if platform is not None else _sys.platform)
        self.findings = []
        self._seen = set()
        self.functions = {}
        self.param_labels = {}
        self.return_taint = {}
        self.module_edges = []
        self.call_edges = {}
        self.global_env = {}
        self.module_stmts = []
        # name -> dotted target, resolved from imports and simple assignments
        self.module_bindings = {}
        self.func_bindings = {}
        self._bindings = {}

    # ------------------------------------------------------------------ API
    def analyze(self):
        try:
            tree = ast.parse(self.src)
        except SyntaxError as exc:
            return None, f"syntax error: {exc.msg} (line {exc.lineno})"
        except (ValueError, RecursionError) as exc:
            return None, f"parse failure: {type(exc).__name__}"
        self.tree = tree
        self.module_stmts = [st for st in tree.body
                             if not isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        self._collect_functions(tree, "")
        self._collect_edges()
        self._build_bindings()
        self._fixpoint()
        # Module-level imports apply from their own line onward: a call before
        # the import would raise NameError at runtime, so it is not a sink.
        self._bindings = {}
        self._run_block(self.module_stmts, dict(self.global_env), collect=True)
        for key in sorted(self.functions):
            node = self.functions[key][0]
            self._bindings = self.func_bindings.get(key, {})
            self._scan_function(node)
        self.findings.sort(key=lambda f: (f.line, f.col, f.rule_id))
        return self.findings, None

    # --------------------------------------------------------------- bindings
    def _build_bindings(self):
        """Collect the import aliases visible in each scope.

        Only imports are resolved up front. Assignment rebindings are applied
        live while scanning, in statement order, so a later rebinding cannot
        retroactively hide (or invent) a sink at an earlier call site.
        """
        self.module_bindings = self._import_bindings(self.module_stmts, {})
        self.func_bindings = {}
        for key in sorted(self.functions):
            node = self.functions[key][0]
            table = self._import_bindings(node.body, self.module_bindings)
            # a parameter or *args/**kwargs name shadows any module-level alias
            for name in self._local_names(node):
                table.pop(name, None)
            self.func_bindings[key] = table

    def _local_names(self, node):
        args = node.args
        names = [a.arg for a in getattr(args, "posonlyargs", []) or []]
        names += [a.arg for a in args.args]
        if args.vararg:
            names.append(args.vararg.arg)
        names += [a.arg for a in args.kwonlyargs]
        if args.kwarg:
            names.append(args.kwarg.arg)
        return names

    @staticmethod
    def _resolve_chain(name, table, hops=4):
        seen = set()
        current = name
        for _ in range(hops):
            head, _, rest = current.partition(".")
            if head not in table or head in seen:
                break
            seen.add(head)
            base = table[head]
            current = f"{base}.{rest}" if rest else base
        return current

    def _dotted_target(self, node, table):
        dn = dotted_name(node)
        if not dn:
            return None
        return self._resolve_chain(dn, table)

    def _bind(self, name, value_node):
        """Record (or clear) a local name binding during the scan."""
        if not isinstance(name, str):
            return
        target = self._dotted_target(value_node, self._current_bindings())
        if target:
            self._bindings[name] = target
        else:
            self._bindings.pop(name, None)

    def _bind_target(self, target, value_node):
        """Update local alias bindings for one assignment target."""
        if isinstance(target, ast.Name):
            self._bind(target.id, value_node)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind_target(elt, value_node)
        elif isinstance(target, ast.Starred):
            self._bind_target(target.value, value_node)

    def _import_bindings(self, stmts, inherited):
        table = dict(inherited)

        def visit(node):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    table[alias.asname or root] = alias.name if alias.asname else root
                return
            if isinstance(node, ast.ImportFrom):
                # relative imports cannot be resolved without package context
                if node.module and not node.level:
                    for alias in node.names:
                        if alias.name == "*":
                            continue
                        table[alias.asname or alias.name] = f"{node.module}.{alias.name}"
                return
            for child in ast.iter_child_nodes(node):
                if isinstance(child, _FLOW_NODES):
                    # nested functions/classes get their own binding scope
                    continue
                visit(child)

        for st in stmts:
            visit(st)
        return table

    def _current_bindings(self):
        return self._bindings or {}

    def _resolve_sink(self, dn):
        """Map an alias-qualified name onto its real dotted target."""
        if not dn:
            return dn
        return self._resolve_chain(dn, self._current_bindings())

    # ------------------------------------------------------------- structure
    def _collect_functions(self, node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                key = f"{prefix}{child.name}"
                self.functions[key] = (child, key)
                child._ia_key = key
                self._collect_functions(child, key + ".")
            elif isinstance(child, ast.ClassDef):
                self._collect_functions(child, child.name + ".")

    @staticmethod
    def _params(node):
        pos = getattr(node, "posonlyargs", []) or []
        return [a.arg for a in pos] + [a.arg for a in node.args.args]

    def _calls_direct(self, stmts):
        """Call nodes belonging to these statements (nested defs excluded)."""
        out = []

        def visit(node):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, _FLOW_NODES):
                    continue
                if isinstance(child, ast.Call):
                    out.append(child)
                visit(child)

        for st in stmts:
            visit(st)
        return out

    def _callee_name(self, call):
        fn = call.func
        if isinstance(fn, ast.Name):
            return self._resolve(fn.id)
        if isinstance(fn, ast.Attribute):
            if isinstance(fn.value, ast.Name) and fn.value.id == "self":
                return self._resolve(fn.attr)
            dotted = dotted_name(fn)
            if dotted and dotted in self.functions:
                return dotted
            return self._resolve(fn.attr)
        return None

    def _resolve(self, hint):
        """Resolve a bare name to a function key (module function or method)."""
        if hint in self.functions:
            return hint
        matches = [key for key in self.functions if key.endswith("." + hint)]
        return matches[0] if len(matches) == 1 else None

    def _collect_edges(self):
        for call in self._calls_direct(self.module_stmts):
            name = self._callee_name(call)
            if name in self.functions:
                self.module_edges.append((name, call))
        self.call_edges = {key: [] for key in self.functions}
        for key in sorted(self.functions):
            node = self.functions[key][0]
            for call in self._calls_direct(node.body):
                name = self._callee_name(call)
                if name in self.functions and name != key:
                    self.call_edges[key].append((name, call))

    # -------------------------------------------------------------- fixpoint
    def _fr(self):
        return frozenset(self.return_taint)

    def _function_env(self, key):
        params = self._params(self.functions[key][0])
        env = dict(self.global_env)
        for index, label in self.param_labels.get(key, {}).items():
            if index < len(params):
                env[params[index]] = label
        return env

    def _propagate(self, env, callee, call):
        params = self._params(self.functions[callee][0])
        labels = self.param_labels.setdefault(callee, {})
        changed = False
        # bound-method call: the receiver is implicit, so arguments shift by one
        offset = 1 if ("." in callee and isinstance(call.func, ast.Attribute)) else 0
        pairs = [(i + offset, arg) for i, arg in enumerate(call.args)]
        for kw in call.keywords:
            if kw.arg in params:
                pairs.append((params.index(kw.arg), kw.value))
        for index, arg in pairs:
            if index >= len(params):
                continue
            tainted, label = expression_taint(arg, env, self._fr(), self._current_bindings())
            if tainted and labels.get(index) != label:
                labels[index] = label
                changed = True
        return changed

    def _fixpoint(self):
        self.global_env = {}
        for _ in range(8):
            changed = False
            genv = dict(self.global_env)
            for callee, call in self.module_edges:
                if self._propagate(genv, callee, call):
                    changed = True
            genv, _, _ = self._run_block(self.module_stmts, genv, collect=False)
            for key, value in genv.items():
                if self.global_env.get(key) != value:
                    self.global_env[key] = value
                    changed = True
            for key in sorted(self.functions):
                node = self.functions[key][0]
                env = self._function_env(key)
                for callee, call in self.call_edges.get(key, []):
                    if self._propagate(env, callee, call):
                        changed = True
                _, ret_t, ret_l = self._run_block(node.body, env, collect=False)
                prev = self.return_taint.get(key)
                if ret_t:
                    if prev != (True, ret_l):
                        self.return_taint[key] = (True, ret_l)
                        changed = True
                elif prev is not None:
                    del self.return_taint[key]
                    changed = True
            if not changed:
                break

    # --------------------------------------------------------------- scanning
    def _scan_function(self, node, collect=True):
        env = self._function_env(getattr(node, "_ia_key", ""))
        self._run_block(node.body, env, collect=collect)

    def _run_block(self, stmts, env, collect):
        env = dict(env)
        ret_t, ret_l = False, None
        for st in stmts:
            env, t, l = self._run_stmt(st, env, collect)
            if t and not ret_t:
                ret_t, ret_l = True, l
        return env, ret_t, ret_l

    def _assign(self, target, tainted, label, env):
        if isinstance(target, ast.Name):
            if tainted:
                env[target.id] = label or "tainted"
            else:
                env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, tainted, label, env)
        elif isinstance(target, ast.Starred):
            self._assign(target.value, tainted, label, env)
        elif isinstance(target, ast.Attribute):
            if isinstance(target.value, ast.Name):
                key = f"{target.value.id}.{target.attr}"
                if tainted:
                    env[key] = label or "tainted"
                else:
                    env.pop(key, None)
        elif isinstance(target, ast.Subscript):
            if isinstance(target.value, ast.Name) and isinstance(target.slice, ast.Constant) \
                    and isinstance(target.slice.value, str):
                key = f"{target.value.id}[{target.slice.value}]"
                if tainted:
                    env[key] = label or "tainted"
                else:
                    env.pop(key, None)

    def _run_stmt(self, node, env, collect):
        if isinstance(node, ast.Import):
            if collect:
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    self._bindings[alias.asname or root] = (
                        alias.name if alias.asname else root)
            return env, False, None
        if isinstance(node, ast.ImportFrom):
            # relative imports cannot be resolved without package context
            if collect and node.module and not node.level:
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    self._bindings[alias.asname or alias.name] = (
                        f"{node.module}.{alias.name}")
            return env, False, None
        if isinstance(node, ast.Assign):
            self._scan_expr(node.value, env, collect)
            tainted, label = expression_taint(node.value, env, self._fr(), self._current_bindings())
            if collect:
                for target in node.targets:
                    self._bind_target(target, node.value)
            for target in node.targets:
                self._assign(target, tainted, label, env)
            return env, False, None
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._scan_expr(node.value, env, collect)
                tainted, label = expression_taint(node.value, env, self._fr(), self._current_bindings())
                if collect:
                    self._bind_target(node.target, node.value)
                self._assign(node.target, tainted, label, env)
            return env, False, None
        if isinstance(node, ast.AugAssign):
            self._scan_expr(node.value, env, collect)
            tainted, label = expression_taint(node.value, env, self._fr(), self._current_bindings())
            if isinstance(node.target, ast.Name):
                current = env.get(node.target.id)
                if tainted or current:
                    env[node.target.id] = label or current or "augmented"
            return env, False, None
        if isinstance(node, ast.Expr):
            self._scan_expr(node.value, env, collect)
            return env, False, None
        if isinstance(node, ast.Return):
            if node.value is not None:
                self._scan_expr(node.value, env, collect)
                tainted, label = expression_taint(node.value, env, self._fr(), self._current_bindings())
                return env, tainted, label
            return env, False, None
        if isinstance(node, _FLOW_NODES):
            return env, False, None
        if isinstance(node, ast.If):
            self._scan_expr(node.test, env, collect)
            body_env, bt, bl = self._run_block(node.body, dict(env), collect)
            else_env, et, el = self._run_block(node.orelse, dict(env), collect)
            env.update(_merge_envs(env, body_env, else_env))
            return env, bt or et, bl or el
        if isinstance(node, (ast.For, ast.AsyncFor)):
            self._scan_expr(node.iter, env, collect)
            tainted, label = expression_taint(node.iter, env, self._fr(), self._current_bindings())
            loop_env = dict(env)
            if tainted:
                self._assign(node.target, True, label or "iterable", loop_env)
            self._run_block(node.body, loop_env, collect)
            self._run_block(node.orelse, dict(loop_env), collect)
            env.update(_merge_envs(env, loop_env))
            return env, False, None
        if isinstance(node, ast.While):
            self._scan_expr(node.test, env, collect)
            loop_env = dict(env)
            self._run_block(node.body, loop_env, collect)
            env.update(_merge_envs(env, loop_env))
            return env, False, None
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._scan_expr(item.context_expr, env, collect)
            self._run_block(node.body, dict(env), collect)
            return env, False, None
        if isinstance(node, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            body_env, _, _ = self._run_block(node.body, dict(env), collect)
            handler_env = dict(env)
            for handler in node.handlers:
                if handler.type is not None:
                    self._scan_expr(handler.type, env, collect)
                self._run_block(handler.body, dict(handler_env), collect)
            else_env, _, _ = self._run_block(node.orelse, dict(env), collect)
            final_env, _, _ = self._run_block(node.finalbody, dict(env), collect)
            env.update(_merge_envs(env, body_env, handler_env, else_env, final_env))
            return env, False, None
        if isinstance(node, ast.Match):
            self._scan_expr(node.subject, env, collect)
            merged = dict(env)
            for case in node.cases:
                case_env = dict(env)
                self._run_block(case.body, case_env, collect)
                merged = _merge_envs(merged, case_env)
            env.update(merged)
            return env, False, None
        if isinstance(node, ast.Delete):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
            return env, False, None
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._scan_expr(child, env, collect)
        return env, False, None

    def _scan_expr(self, node, env, collect):
        if node is None:
            return
        if isinstance(node, ast.Call):
            if collect:
                self._check_sink(node, env)
            self._scan_expr(node.func, env, collect)
            for arg in node.args:
                self._scan_expr(arg, env, collect)
            for kw in node.keywords:
                self._scan_expr(kw.value, env, collect)
            return
        if isinstance(node, ast.Lambda):
            return
        if isinstance(node, ast.expr):
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
                for generator in node.generators:
                    self._scan_expr(generator.iter, env, collect)
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._scan_expr(child, env, collect)

    # ----------------------------------------------------------------- sinks
    def _is_windows(self):
        return self.platform.lower().startswith("win")

    def _add(self, rule_id, call, source, sink, note=""):
        meta = RULE_META[rule_id]
        segment = ast.get_source_segment(self.src, call)
        if not segment and 1 <= call.lineno <= len(self.lines):
            segment = self.lines[call.lineno - 1].strip()
        evidence = " ".join((segment or "").split())
        finding = Finding(
            rule_id=rule_id, cwe=meta[0], severity=meta[1],
            line=call.lineno, col=call.col_offset,
            evidence=evidence, sink=f"{sink}()", source=source or "unresolved",
            message=message_for(rule_id, source or "unresolved") + note,
        )
        key = (finding.rule_id, finding.line, finding.col, finding.sink)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(finding)

    def _check_sink(self, call, env):
        dn = dotted_name(call.func)
        if dn is None and isinstance(call.func, ast.Attribute):
            dn = call.func.attr
        if not dn:
            return
        dn = self._resolve_sink(dn)
        args = list(call.args)
        kwargs = {kw.arg: kw.value for kw in call.keywords if kw.arg is not None}
        shell_node = kwargs.get("shell")
        if shell_node is None:
            shell_true, shell_unknown = False, False
        elif isinstance(shell_node, ast.Constant):
            shell_true, shell_unknown = shell_node.value is True, False
        else:
            # unknown truthiness: treat as potentially shell-executing
            shell_true, shell_unknown = True, True
        note = " The shell= argument is not a literal False." if shell_unknown else ""
        fr = self._fr()

        if dn in SUBPROCESS_SINKS or dn == "asyncio.create_subprocess_exec":
            executable = kwargs.get("executable")
            if executable is not None:
                tainted, label = expression_taint(executable, env, fr, self._current_bindings())
                if tainted:
                    # attacker-influenced program name: the launcher runs that binary
                    self._add("SIA-88-02", call, label, dn)

        if dn in ("os.system", "os.popen"):
            if args:
                tainted, label = expression_taint(args[0], env, fr, self._current_bindings())
                if tainted:
                    self._add("SIA-78-01" if dn == "os.system" else "SIA-78-02",
                              call, label, dn)
            return
        if dn in EXEC_SINKS:
            for arg in args:
                tainted, label = expression_taint(arg, env, fr, self._current_bindings())
                if tainted:
                    self._add("SIA-78-05", call, label, dn)
                    return
            return
        if dn == "asyncio.create_subprocess_shell":
            if args:
                tainted, label = expression_taint(args[0], env, fr, self._current_bindings())
                if tainted:
                    self._add("SIA-78-04", call, label, dn)
            return
        if dn in EVAL_SINKS:
            for arg in args:
                tainted, label = expression_taint(arg, env, fr, self._current_bindings())
                if tainted:
                    self._add("SIA-95-01", call, label, dn)
                    return
            return
        if dn in ("subprocess.getoutput", "subprocess.getstatusoutput"):
            # these helpers run their string argument through the system shell
            if args:
                tainted, label = expression_taint(args[0], env, fr, self._current_bindings())
                if tainted:
                    self._add("SIA-78-03", call, label, dn, note)
                    if self._is_windows():
                        self._add("SIA-88-03", call, label, dn)
            return
        if dn in SUBPROCESS_SINKS or dn == "asyncio.create_subprocess_exec":
            cmd = args[0] if args else kwargs.get("args")
            if cmd is None:
                return
            if isinstance(cmd, (ast.List, ast.Tuple)):
                is_shell, shell_cmd_index = _shell_argv(cmd.elts)
                elems = []
                for index, elem in enumerate(cmd.elts):
                    # A starred element unpacks a tainted collection; the taint
                    # lives on the expression being unpacked, not the Starred.
                    target = elem.value if isinstance(elem, ast.Starred) else elem
                    elems.append(target)
                    tainted, label = expression_taint(target, env, fr, self._current_bindings())
                    if not tainted:
                        continue
                    if shell_true:
                        self._add("SIA-78-03", call, label, dn, note)
                    elif shell_cmd_index == index:
                        # `sh -c <tainted>` re-parses the value as shell syntax.
                        # It is also an argument reaching an external program,
                        # so both classes are evidenced here.
                        self._add("SIA-78-03", call, label, dn)
                        self._add("SIA-88-01", call, label, dn)
                    elif is_shell and index == 1:
                        # `sh <tainted>` treats the value as a script path.
                        self._add("SIA-88-02", call, label, dn)
                    else:
                        self._add("SIA-88-02" if index == 0 else "SIA-88-01",
                                  call, label, dn)
                if shell_true and elems and self._is_windows():
                    labels = [expression_taint(e, env, fr, self._current_bindings())[1] for e in elems]
                    if any(labels):
                        self._add("SIA-88-03", call, ", ".join(x for x in labels if x), dn)
                return
            tainted, label = expression_taint(cmd, env, fr, self._current_bindings())
            if tainted:
                if shell_true:
                    self._add("SIA-78-03", call, label, dn, note)
                    if self._is_windows():
                        self._add("SIA-88-03", call, label, dn)
                else:
                    self._add("SIA-88-02", call, label, dn)
