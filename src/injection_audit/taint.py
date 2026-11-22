"""Taint expression evaluator (language-agnostic helpers live with the parser)."""
import ast

SOURCE_CALL_LABELS = {
    "os.getenv": "os.getenv(...)",
    "os.environ.get": "os.environ.get(...)",
    "input": "input()",
    "sys.stdin.read": "sys.stdin.read()",
    "sys.stdin.readline": "sys.stdin.readline()",
    "sys.stdin.readlines": "sys.stdin.readlines()",
}

SOURCE_ATTR_LABELS = {
    "sys.argv", "sys.stdin",
    "request.args", "request.form", "request.values", "request.json",
    "request.GET", "request.POST", "request.cookies", "request.headers",
    "request.data", "request.files", "request.query_params",
}

SANITIZER_CALLS = {"shlex.quote", "pipes.quote", "shellguard.quote"}


def is_source_attribute(name):
    """True when a dotted attribute names a web-request input.

    Accepts the literal forms (`request.args`), the framework-qualified forms
    (`flask.request.args`) and any suffix under a name bound to a request
    object, so an aliased request stays a recognised source.
    """
    if not name:
        return False
    if name in SOURCE_ATTR_LABELS:
        return True
    head, _, tail = name.partition(".")
    if head in ("request", "req"):
        return bool(tail)
    return name.startswith(("flask.request.", "django."))


def dotted_name(node):
    """Return 'os.path.join' for Attribute chains rooted at a Name, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def resolve_name(name, bindings, hops=4):
    """Follow alias bindings: `import os as o; o.getenv()` -> os.getenv."""
    if not name or not bindings:
        return name
    seen = set()
    current = name
    for _ in range(hops):
        head, _, rest = current.partition(".")
        if head not in bindings or head in seen:
            break
        seen.add(head)
        base = bindings[head]
        current = f"{base}.{rest}" if rest else base
    return current


def _join_labels(a, b):
    return " + ".join(x for x in (a, b) if x) or "tainted"


def expression_taint(node, env, func_returns=frozenset(), bindings=None):
    """Evaluate (tainted, provenance-label) for an expression under env.

    `bindings` maps local names onto their real dotted targets, so a source
    reached through an import alias is still treated as untrusted.
    """
    bindings = bindings or {}
    if node is None:
        return (False, None)
    if isinstance(node, ast.Constant):
        return (False, None)
    if isinstance(node, ast.Name):
        label = env.get(node.id)
        return (label is not None, label)
    if isinstance(node, ast.Attribute):
        if isinstance(node.value, ast.Name):
            stored = env.get(f"{node.value.id}.{node.attr}")
            if stored:
                return (True, stored)
        base_t, base_l = expression_taint(node.value, env, func_returns, bindings)
        if base_t:
            return (True, f"{base_l}.{node.attr}")
        dn = dotted_name(node)
        resolved = resolve_name(dn, bindings)
        if is_source_attribute(resolved):
            return (True, resolved)
        return (False, None)
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name) and isinstance(node.slice, ast.Constant) \
                and isinstance(node.slice.value, str):
            stored = env.get(f"{node.value.id}[{node.slice.value}]")
            if stored:
                return (True, stored)
        base_t, base_l = expression_taint(node.value, env, func_returns, bindings)
        if base_t:
            return (True, f"{base_l}[...]")
        dn = dotted_name(node.value)
        resolved = resolve_name(dn, bindings)
        if resolved in ("sys.argv", "os.environ"):
            return (True, f"{resolved}[...]")
        return (False, None)
    if isinstance(node, ast.BinOp):
        lt, ll = expression_taint(node.left, env, func_returns, bindings)
        rt, rl = expression_taint(node.right, env, func_returns, bindings)
        if lt or rt:
            return (True, _join_labels(ll, rl))
        return (False, None)
    if isinstance(node, ast.JoinedStr):
        for value in node.values:
            t, _ = expression_taint(value, env, func_returns, bindings)
            if t:
                return (True, 'f"..."')
        return (False, None)
    if isinstance(node, ast.FormattedValue):
        return expression_taint(node.value, env, func_returns, bindings)
    if isinstance(node, ast.Call):
        return _call_taint(node, env, func_returns, bindings)
    if isinstance(node, ast.IfExp):
        bt, bl = expression_taint(node.body, env, func_returns, bindings)
        ot, ol = expression_taint(node.orelse, env, func_returns, bindings)
        if bt or ot:
            return (True, bl or ol)
        return (False, None)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        for elt in node.elts:
            t, l = expression_taint(elt, env, func_returns, bindings)
            if t:
                return (True, l)
        return (False, None)
    if isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values):
            t, l = expression_taint(key, env, func_returns, bindings)
            if t:
                return (True, l)
            t, l = expression_taint(value, env, func_returns, bindings)
            if t:
                return (True, l)
        return (False, None)
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        for generator in node.generators:
            tainted, label = expression_taint(generator.iter, env, func_returns, bindings)
            if tainted:
                return (True, label)
        return expression_taint(node.elt, env, func_returns, bindings)
    if isinstance(node, ast.DictComp):
        for generator in node.generators:
            tainted, label = expression_taint(generator.iter, env, func_returns, bindings)
            if tainted:
                return (True, label)
        tainted, label = expression_taint(node.key, env, func_returns, bindings)
        if tainted:
            return (True, label)
        return expression_taint(node.value, env, func_returns, bindings)
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            t, l = expression_taint(value, env, func_returns, bindings)
            if t:
                return (True, l)
        return (False, None)
    if isinstance(node, ast.Compare):
        return expression_taint(node.left, env, func_returns, bindings)
    if isinstance(node, (ast.Await, ast.Starred, ast.NamedExpr)):
        return expression_taint(node.value, env, func_returns, bindings)
    if isinstance(node, ast.UnaryOp):
        return expression_taint(node.operand, env, func_returns, bindings)
    return (False, None)


def _call_taint(node, env, func_returns, bindings=None):
    bindings = bindings or {}
    fn = node.func
    dn = dotted_name(fn)
    resolved = resolve_name(dn, bindings)
    if resolved in SANITIZER_CALLS or (isinstance(fn, ast.Name) and fn.id == "quote"):
        return (False, None)
    if resolved in SOURCE_CALL_LABELS:
        return (True, SOURCE_CALL_LABELS[resolved])
    if resolved and resolved.endswith("parse_args"):
        return (True, "args")
    if resolved:
        root = resolved.split(".")[0]
        if root in ("request", "req") or resolved.startswith(("flask.request", "django")):
            return (True, f"{resolved}(...)")
    if resolved and resolved.split(".")[-1] in ("recv", "recvfrom", "readline", "readlines", "read"):
        # socket-style receivers: only tainted if the receiver itself is tainted,
        # handled below; a bare name like sock.recv() stays untracked here.
        pass
    # method call on a tainted receiver propagates taint
    if isinstance(fn, ast.Attribute):
        bt, bl = expression_taint(fn.value, env, func_returns, bindings)
        if bt:
            return (True, f"{bl}.{fn.attr}(...)")
    # any tainted argument makes the result tainted (covers open(user_path).read())
    first_label = None
    for arg in node.args:
        t, l = expression_taint(arg, env, func_returns, bindings)
        if t and first_label is None:
            first_label = l
    for kw in node.keywords:
        t, l = expression_taint(kw.value, env, func_returns, bindings)
        if t and first_label is None:
            first_label = l
    if first_label is not None:
        return (True, f"{dn or 'call'}({first_label}, ...)")
    for candidate in (resolved, dn):
        if candidate and candidate in func_returns:
            return (True, f"{candidate}()")
    return (False, None)
