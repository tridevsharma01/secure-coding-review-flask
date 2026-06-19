import ast
import re
import sys


RULES = []


def rule(rule_id, title, severity, cwe):
    def deco(fn):
        RULES.append({"id": rule_id, "title": title, "severity": severity, "cwe": cwe, "check": fn})
        return fn
    return deco


class Scanner(ast.NodeVisitor):
    def __init__(self, source, filename):
        self.source = source
        self.lines = source.splitlines()
        self.filename = filename
        self.findings = []

    def add(self, rule_id, title, severity, cwe, lineno, snippet):
        self.findings.append({
            "rule_id": rule_id, "title": title, "severity": severity,
            "cwe": cwe, "line": lineno, "snippet": snippet.strip(),
        })

    def visit_Call(self, node):
        func_name = self._call_name(node)

        # subprocess / os.system with shell=True or f-string/concat command
        if func_name in ("subprocess.check_output", "subprocess.run", "subprocess.call", "subprocess.Popen", "os.system"):
            shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            first_arg = node.args[0] if node.args else None
            dynamic = isinstance(first_arg, (ast.JoinedStr, ast.BinOp))
            if func_name == "os.system" or shell_true or dynamic:
                self.add("SEC-CMD-INJ", "Possible OS Command Injection", "Critical",
                         "CWE-78", node.lineno, self.lines[node.lineno - 1])

        if func_name in ("pickle.loads", "pickle.load"):
            self.add("SEC-DESERIAL", "Insecure Deserialization (pickle)", "Critical",
                     "CWE-502", node.lineno, self.lines[node.lineno - 1])

        if func_name in ("hashlib.md5", "hashlib.sha1"):
            self.add("SEC-WEAK-HASH", "Weak Hashing Algorithm", "Medium",
                     "CWE-327", node.lineno, self.lines[node.lineno - 1])

        if func_name in ("eval", "exec"):
            self.add("SEC-EVAL", "Use of eval()/exec() on possibly untrusted input", "Critical",
                     "CWE-95", node.lineno, self.lines[node.lineno - 1])

        if func_name == "execute" or func_name.endswith(".execute"):
            arg = node.args[0] if node.args else None
            if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                self.add("SEC-SQLI", "Possible SQL Injection (dynamic query string)", "Critical",
                         "CWE-89", node.lineno, self.lines[node.lineno - 1])

        if func_name == "app.run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self.add("SEC-DEBUG", "Debug mode enabled in app.run()", "High",
                             "CWE-489", node.lineno, self.lines[node.lineno - 1])
                if kw.arg == "host" and isinstance(kw.value, ast.Constant) and kw.value.value == "0.0.0.0":
                    self.add("SEC-BIND-ALL", "Server bound to all network interfaces", "Low",
                             "CWE-200", node.lineno, self.lines[node.lineno - 1])

        self.generic_visit(node)

    def visit_Assign(self, node):
        # crude hardcoded secret detector: NAME = "literal" where NAME hints at a secret
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                name = getattr(target, "attr", None) or getattr(target, "id", None) or ""
                if re.search(r"(secret|password|passwd|api_key|token)", name, re.IGNORECASE):
                    self.add("SEC-HARDCODED-SECRET", "Hardcoded credential/secret", "High",
                             "CWE-798", node.lineno, self.lines[node.lineno - 1])
        self.generic_visit(node)

    def _call_name(self, node):
        f = node.func
        if isinstance(f, ast.Attribute):
            base = self._dotted(f.value)
            return f"{base}.{f.attr}" if base else f.attr
        if isinstance(f, ast.Name):
            return f.id
        return ""

    def _dotted(self, node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._dotted(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return ""


def scan_file(path):
    with open(path, "r") as f:
        source = f.read()
    tree = ast.parse(source, filename=path)
    scanner = Scanner(source, path)
    scanner.visit(tree)
    return scanner.findings


def main():
    if len(sys.argv) != 2:
        print("Usage: python simple_security_scanner.py <file.py>")
        sys.exit(1)

    path = sys.argv[1]
    findings = scan_file(path)
    findings.sort(key=lambda f: f["line"])

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"\nStatic Analysis Report: {path}")
    print("=" * 60)
    for f in findings:
        print(f"[{f['severity']:>8}] {f['rule_id']:<20} line {f['line']:<4} {f['title']} ({f['cwe']})")
        print(f"           > {f['snippet']}")
    print("=" * 60)
    print(f"Total findings: {len(findings)}  |  " +
          "  ".join(f"{k}: {v}" for k, v in sorted(counts.items(), key=lambda kv: sev_order.get(kv[0], 9))))


if __name__ == "__main__":
    main()