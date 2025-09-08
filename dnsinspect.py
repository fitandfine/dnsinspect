#!/usr/bin/env python3
"""
DNS Inspector Pro - Enhanced Version
------------------------------------
A GUI tool to inspect DNS records for a domain, run diagnostics,
and fetch results in real-time with user-friendly output.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import dns.resolver
import threading
import time
import os
import queue

# Supported record types
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA"]
EXTRA_CHECKS = ["_dmarc"]

# Thread-safe queue for bulk results
bulk_queue = queue.Queue()

def build_resolver(server=None, verbose=False):
    """Builds a DNS resolver, optionally using a custom server."""
    resolver = dns.resolver.Resolver()
    if server:
        resolver.nameservers = [server]
    if verbose:
        print(f"[DEBUG] Using nameservers: {resolver.nameservers}")
    return resolver

def query_record(resolver, domain, rtype, verbose=False):
    """Queries a DNS record of given type for a domain."""
    try:
        if verbose:
            print(f"[DEBUG] Querying {rtype} for {domain}")
        answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
        results = []
        if answers.rrset:
            ttl = answers.rrset.ttl
            for rdata in answers:
                results.append({"type": rtype, "ttl": ttl, "value": str(rdata)})
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
    """Gets authoritative nameservers for a domain."""
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        return [str(r.target).strip(".") for r in ns_records]
    except Exception:
        return []

def diagnostics(domain, results):
    """Runs diagnostic checks and returns issues."""
    issues = []
    explanations = {
        "Missing apex A/AAAA": "No IP address records found for the root domain.",
        "Apex CNAME found": "CNAME at root breaks DNS standards.",
        "MX host unresolved": "Your mail server hostname doesn't resolve.",
        "Missing SPF": "No SPF record found.",
        "Missing DMARC": "No DMARC policy found.",
        "Too few nameservers": "You should have at least 2 NS records.",
        "NS host missing glue": "Your NS hostname doesn't resolve.",
        "High TTL": "Long TTL delays propagation."
    }

    if not results.get("A") and not results.get("AAAA"):
        issues.append(("Missing apex A/AAAA", f"Add an A or AAAA record for {domain}"))

    if results.get("CNAME"):
        issues.append(("Apex CNAME found", "Avoid using CNAME at apex"))

    for mx in results.get("MX", []):
        if "error" not in mx and "value" in mx:
            host = mx["value"].split()[-1]
            r = query_record(build_resolver(), host, "A")
            if not r:
                issues.append(("MX host unresolved", f"Add A/AAAA for {host}"))

    txt_records = " ".join([r["value"] for r in results.get("TXT", []) if "value" in r])
    if "v=spf1" not in txt_records:
        issues.append(("Missing SPF", "Add TXT record with v=spf1 policy"))

    if not results.get("_dmarc.TXT"):
        issues.append(("Missing DMARC", f"Add TXT record for _dmarc.{domain}"))

    if len(results.get("NS", [])) < 2:
        issues.append(("Too few nameservers", "Use at least 2 NS records"))

    for ns in results.get("NS", []):
        if "error" not in ns and "value" in ns:
            ns_host = ns["value"]
            r = query_record(build_resolver(), ns_host, "A")
            if not r:
                issues.append(("NS host missing glue", f"Add A/AAAA for {ns_host}"))

    for rtype, recs in results.items():
        for rec in recs:
            if "ttl" in rec and rec["ttl"] and rec["ttl"] > 86400:
                issues.append(("High TTL", f"{rtype} {rec.get('value','')} TTL={rec['ttl']}"))

    return [(t, f, explanations.get(t, "")) for t, f in issues]

class DNSInspectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Inspector Pro")

        self.stop_refresh = threading.Event()

        frame_input = ttk.Frame(root)
        frame_input.pack(fill="x", padx=10, pady=5)
        ttk.Label(frame_input, text="Domain:").pack(side="left")
        self.domain_var = tk.StringVar()
        ttk.Entry(frame_input, textvariable=self.domain_var, width=30).pack(side="left", padx=5)

        ttk.Label(frame_input, text="Auto-refresh (sec):").pack(side="left", padx=5)
        self.refresh_var = tk.StringVar(value="0")
        ttk.Entry(frame_input, textvariable=self.refresh_var, width=5).pack(side="left")

        frame_opts = ttk.LabelFrame(root, text="Options")
        frame_opts.pack(fill="x", padx=10, pady=5)
        self.var_authoritative = tk.BooleanVar()
        ttk.Checkbutton(frame_opts, text="Query Authoritative", variable=self.var_authoritative).pack(side="left")
        self.var_diagnostics = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame_opts, text="Diagnostics", variable=self.var_diagnostics).pack(side="left")
        self.var_verbose = tk.BooleanVar()
        ttk.Checkbutton(frame_opts, text="Verbose", variable=self.var_verbose).pack(side="left")

        frame_records = ttk.LabelFrame(root, text="Record Types")
        frame_records.pack(fill="x", padx=10, pady=5)
        self.record_vars = {}
        for rtype in RECORD_TYPES:
            var = tk.BooleanVar(value=True)
            self.record_vars[rtype] = var
            ttk.Checkbutton(frame_records, text=rtype, variable=var).pack(side="left")

        frame_buttons = ttk.Frame(root)
        frame_buttons.pack(fill="x", padx=10, pady=5)
        ttk.Button(frame_buttons, text="Run", command=self.run_once).pack(side="left")
        ttk.Button(frame_buttons, text="Save Output", command=self.save_output).pack(side="left")
        ttk.Button(frame_buttons, text="Load Bulk Domains", command=self.load_bulk).pack(side="left")
        ttk.Button(frame_buttons, text="Stop Auto", command=self.stop_auto_refresh).pack(side="left")

        frame_search = ttk.Frame(root)
        frame_search.pack(fill="x", padx=10, pady=5)
        ttk.Label(frame_search, text="Search Output:").pack(side="left")
        self.search_var = tk.StringVar()
        ttk.Entry(frame_search, textvariable=self.search_var, width=20).pack(side="left")
        ttk.Button(frame_search, text="Find", command=self.search_text).pack(side="left")

        self.output = scrolledtext.ScrolledText(root, wrap="word", height=25)
        self.output.pack(fill="both", expand=True, padx=10, pady=5)

        # Progress bar for bulk queries
        self.progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=5)

        # Poll the queue periodically for results from threads
        self.root.after(500, self.process_bulk_queue)

        # Safe exit
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)

    def run_once(self):
        """Runs inspection once, optionally auto-refreshing."""
        domain = self.domain_var.get().strip(".")
        if not domain:
            self.log("Enter a domain.\n", "error")
            return
        self.output.delete("1.0", tk.END)
        self.run_inspection(domain)
        interval = int(self.refresh_var.get() or "0")
        if interval > 0:
            threading.Thread(target=self.auto_refresh, args=(domain, interval), daemon=True).start()

    def run_inspection(self, domain):
        """Performs DNS inspection and logs results."""
        self.log(f"\n=== DNS Inspection for {domain} ===\n\n", "header")
        resolver = build_resolver(verbose=self.var_verbose.get())
        if self.var_authoritative.get():
            ns_hosts = get_authoritative_nameservers(domain)
            if ns_hosts:
                resolver.nameservers.clear()
                for ns in ns_hosts:
                    a_rec = query_record(build_resolver(), ns, "A")
                    if a_rec and "value" in a_rec[0]:
                        resolver.nameservers.append(a_rec[0]["value"])
        results = {}
        for rtype, var in self.record_vars.items():
            if var.get():
                results[rtype] = query_record(resolver, domain, rtype, self.var_verbose.get())
        for sub in EXTRA_CHECKS:
            fqdn = f"{sub}.{domain}"
            results[fqdn + ".TXT"] = query_record(resolver, fqdn, "TXT")
        for rtype, recs in results.items():
            self.log(f"[{rtype}]\n", "section")
            if not recs:
                self.log("  (no records)\n")
            for rec in recs:
                if "error" in rec:
                    self.log(f"  ERROR: {rec['error']}\n", "error")
                elif "value" in rec:
                    self.log(f"  TTL={rec.get('ttl')}  {rec['value']}\n")
        if self.var_diagnostics.get():
            self.log("\n=== Diagnostics ===\n", "header")
            for title, fix, expl in diagnostics(domain, results):
                self.log(f"- {title}: {fix}\nExplanation: {expl}\n\n", "warn")

    def auto_refresh(self, domain, interval):
        """Keeps refreshing inspection at interval seconds."""
        self.stop_refresh.clear()
        while not self.stop_refresh.is_set():
            time.sleep(interval)
            self.output.delete("1.0", tk.END)
            self.run_inspection(domain)

    def stop_auto_refresh(self):
        """Stops auto-refresh loop."""
        self.stop_refresh.set()

    def save_output(self):
        """Saves current output to file."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            if os.path.exists(file_path):
                if not messagebox.askyesno("Overwrite?", f"{file_path} exists. Overwrite?"):
                    return
            with open(file_path, "w") as f:
                f.write(self.output.get("1.0", tk.END))
            self.log(f"Output saved to {file_path}\n", "ok")

    def load_bulk(self):
        """Loads domains from file and queries them asynchronously."""
        file_path = filedialog.askopenfilename()
        if file_path and os.path.isfile(file_path):
            with open(file_path) as f:
                domains = [line.strip() for line in f if line.strip()]
            self.progress["maximum"] = len(domains)
            self.progress["value"] = 0
            for domain in domains:
                threading.Thread(target=self.run_bulk_domain, args=(domain,), daemon=True).start()

    def run_bulk_domain(self, domain):
        """Runs inspection for a single domain and pushes result to queue."""
        from io import StringIO
        buffer = StringIO()
        resolver = build_resolver()
        results = {}
        for rtype in RECORD_TYPES:
            results[rtype] = query_record(resolver, domain, rtype)
        for sub in EXTRA_CHECKS:
            fqdn = f"{sub}.{domain}"
            results[fqdn + ".TXT"] = query_record(resolver, fqdn, "TXT")
        bulk_queue.put((domain, results))

    def process_bulk_queue(self):
        """Processes results from background threads."""
        try:
            while True:
                domain, results = bulk_queue.get_nowait()
                self.log(f"\n=== Bulk: {domain} ===\n", "header")
                for rtype, recs in results.items():
                    self.log(f"[{rtype}]\n", "section")
                    if not recs:
                        self.log("  (no records)\n")
                    for rec in recs:
                        if "error" in rec:
                            self.log(f"  ERROR: {rec['error']}\n", "error")
                        elif "value" in rec:
                            self.log(f"  TTL={rec.get('ttl')}  {rec['value']}\n")
                self.progress["value"] += 1
        except queue.Empty:
            pass
        finally:
            self.root.after(500, self.process_bulk_queue)

    def search_text(self):
        """Highlights text matches in output."""
        target = self.search_var.get()
        self.output.tag_remove("search", "1.0", tk.END)
        if target:
            idx = "1.0"
            while True:
                idx = self.output.search(target, idx, nocase=1, stopindex=tk.END)
                if not idx:
                    break
                lastidx = f"{idx}+{len(target)}c"
                self.output.tag_add("search", idx, lastidx)
                idx = lastidx
            self.output.tag_config("search", background="yellow", foreground="black")

    def log(self, text, style=None):
        """Appends text with optional style to output box."""
        tag = None
        if style and style not in self.output.tag_names():
            colors = {
                "error": "red", "warn": "orange",
                "ok": "green", "header": "blue",
                "section": "purple"
            }
            if style in colors:
                self.output.tag_configure(style, foreground=colors[style])
            tag = style
        elif style:
            tag = style
        self.output.insert(tk.END, text, tag)
        self.output.see(tk.END)

    def on_exit(self):
        """Graceful shutdown."""
        self.stop_auto_refresh()
        self.root.destroy()

if __name__ == "__main__":
    try:
        import dns
    except ImportError:
        print("Please install dnspython: pip install dnspython")
        exit(1)
    root = tk.Tk()
    app = DNSInspectorApp(root)
    root.mainloop()
