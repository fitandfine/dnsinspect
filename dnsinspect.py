#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext
import dns.resolver
import dns.exception
import dns.name

# ===== DNS Logic =====
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA"]
EXTRA_CHECKS = ["_dmarc"]

def build_resolver(server=None):
    resolver = dns.resolver.Resolver()
    if server:
        resolver.nameservers = [server]
    return resolver

def query_record(resolver, domain, rtype):
    try:
        answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
        results = []
        for rdata in answers:
            results.append({
                "type": rtype,
                "ttl": answers.rrset.ttl if answers.rrset else None,
                "value": str(rdata)
            })
        return results
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return [{"type": rtype, "error": "NXDOMAIN"}]
    except dns.resolver.LifetimeTimeout:
        return [{"type": rtype, "error": "Timeout"}]
    except Exception as e:
        return [{"type": rtype, "error": str(e)}]

def get_authoritative_nameservers(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        return [str(r.target) for r in ns_records]
    except Exception:
        return []

def diagnostics(domain, results):
    issues = []
    if not results.get("A") and not results.get("AAAA"):
        issues.append(("Missing apex A/AAAA", f"Add an A or AAAA record for {domain}"))
    if results.get("CNAME"):
        issues.append(("Apex CNAME found", "Avoid using CNAME at apex; it may break MX/NS"))
    for mx in results.get("MX", []):
        if "error" not in mx:
            host = mx["value"].split()[-1]
            r = query_record(build_resolver(), host, "A")
            if not r:
                issues.append(("MX host unresolved", f"Add A/AAAA for {host}"))
    txt_records = " ".join([r["value"] for r in results.get("TXT", [])])
    if "v=spf1" not in txt_records:
        issues.append(("Missing SPF", "Add a TXT record with v=spf1 policy"))
    if not results.get("_dmarc.TXT"):
        issues.append(("Missing DMARC", "Add a TXT record for _dmarc." + domain))
    if len(results.get("NS", [])) < 2:
        issues.append(("Too few nameservers", "Use at least 2 NS records"))
    for ns in results.get("NS", []):
        if "error" not in ns:
            ns_host = ns["value"]
            r = query_record(build_resolver(), ns_host, "A")
            if not r:
                issues.append(("NS host missing glue", f"Add A/AAAA for {ns_host}"))
    for rtype, recs in results.items():
        for rec in recs:
            if rec.get("ttl", 0) and rec["ttl"] > 86400:
                issues.append(("High TTL", f"{rtype} record {rec['value']} TTL={rec['ttl']}"))
    return issues

# ===== GUI App =====
class DNSInspectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Inspector")

        # Input
        frame_input = ttk.Frame(root)
        frame_input.pack(fill="x", padx=10, pady=5)
        ttk.Label(frame_input, text="Domain:").pack(side="left")
        self.domain_var = tk.StringVar()
        ttk.Entry(frame_input, textvariable=self.domain_var, width=30).pack(side="left", padx=5)

        # Options
        frame_opts = ttk.LabelFrame(root, text="Options")
        frame_opts.pack(fill="x", padx=10, pady=5)
        self.var_authoritative = tk.BooleanVar()
        ttk.Checkbutton(frame_opts, text="Query Authoritative Nameservers", variable=self.var_authoritative).pack(anchor="w")
        self.var_diagnostics = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame_opts, text="Show Diagnostics", variable=self.var_diagnostics).pack(anchor="w")

        # Record type checkboxes
        self.record_vars = {}
        frame_records = ttk.LabelFrame(root, text="Record Types")
        frame_records.pack(fill="x", padx=10, pady=5)
        for rtype in RECORD_TYPES:
            var = tk.BooleanVar(value=True)
            self.record_vars[rtype] = var
            ttk.Checkbutton(frame_records, text=rtype, variable=var).pack(side="left")

        # Output area
        self.output = scrolledtext.ScrolledText(root, wrap="word", height=25)
        self.output.pack(fill="both", expand=True, padx=10, pady=5)

        # Buttons
        frame_buttons = ttk.Frame(root)
        frame_buttons.pack(fill="x", padx=10, pady=5)
        ttk.Button(frame_buttons, text="Run", command=self.run_inspection).pack(side="left")
        ttk.Button(frame_buttons, text="Clear", command=lambda: self.output.delete("1.0", tk.END)).pack(side="left")

    def run_inspection(self):
        domain = self.domain_var.get().strip(".")
        if not domain:
            self.log("Please enter a domain.\n", "error")
            return

        self.output.delete("1.0", tk.END)
        self.log(f"=== DNS Inspection for {domain} ===\n\n", "header")

        # Resolver selection
        if self.var_authoritative.get():
            ns_hosts = get_authoritative_nameservers(domain)
            if not ns_hosts:
                self.log("Could not find authoritative nameservers.\n", "error")
                return
            resolver = build_resolver()
            resolver.nameservers = []
            for ns in ns_hosts:
                a_records = query_record(build_resolver(), ns, "A")
                if a_records:
                    resolver.nameservers.append(a_records[0]["value"])
        else:
            resolver = build_resolver()

        results = {}
        for rtype, var in self.record_vars.items():
            if var.get():
                results[rtype] = query_record(resolver, domain, rtype)

        for sub in EXTRA_CHECKS:
            fqdn = f"{sub}.{domain}"
            results[fqdn + ".TXT"] = query_record(resolver, fqdn, "TXT")

        # Output records
        for rtype, recs in results.items():
            self.log(f"[{rtype}]\n", "section")
            if not recs:
                self.log("  (no records)\n")
            for rec in recs:
                if "error" in rec:
                    self.log(f"  ERROR: {rec['error']}\n", "error")
                else:
                    self.log(f"  TTL={rec['ttl']}  {rec['value']}\n")

        # Diagnostics
        if self.var_diagnostics.get():
            self.log("\n=== Diagnostics ===\n", "header")
            issues = diagnostics(domain, results)
            if not issues:
                self.log("No obvious problems found.\n", "ok")
            else:
                for title, fix in issues:
                    self.log(f"- {title}: {fix}\n", "warn")

    def log(self, text, style=None):
        tag = None
        if style:
            tag = style
            # Configure tag colors only if not already configured
            if not tag in self.output.tag_names():
                colors = {
                    "error": "red",
                    "warn": "orange",
                    "ok": "green",
                    "header": "blue",
                    "section": "purple"
                }
                if tag in colors:
                    self.output.tag_configure(tag, foreground=colors[tag])
        self.output.insert(tk.END, text, tag)
        self.output.see(tk.END)


# ===== Main Run =====
if __name__ == "__main__":
    import sys
    try:
        import dns
    except ImportError:
        print("Please install dnspython: pip install dnspython")
        sys.exit(1)

    root = tk.Tk()
    app = DNSInspectorApp(root)
    root.mainloop()
