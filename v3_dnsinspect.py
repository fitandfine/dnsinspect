#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import dns.resolver
import dns.reversename
import threading
import subprocess
import os

# ===== Config =====
RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA"]
EXTRA_CHECKS = ["_dmarc"]

# ===== DNS Functions =====
def build_resolver(server=None, verbose=False):
    resolver = dns.resolver.Resolver()
    if server:
        resolver.nameservers = [server]
    if verbose:
        return resolver, resolver.nameservers
    return resolver, []

def query_record(resolver, domain, rtype, verbose=False):
    results = []
    try:
        if verbose:
            results.append({"value": f"Querying {rtype} for {domain}"})
        answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
        ttl = answers.rrset.ttl if answers.rrset else None
        for rdata in answers:
            results.append({"type": rtype, "ttl": ttl, "value": str(rdata)})
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        results.append({"type": rtype, "error": "NXDOMAIN"})
    except dns.resolver.LifetimeTimeout:
        results.append({"type": rtype, "error": "Timeout"})
    except Exception as e:
        results.append({"type": rtype, "error": str(e)})
    return results

def get_authoritative_nameservers(domain):
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        return [str(r.target).strip(".") for r in ns_records]
    except Exception:
        return []

def diagnostics(domain, results):
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
            r = query_record(build_resolver()[0], host, "A")
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
            r = query_record(build_resolver()[0], ns_host, "A")
            if not r:
                issues.append(("NS host missing glue", f"Add A/AAAA for {ns_host}"))
    for rtype, recs in results.items():
        for rec in recs:
            if rec.get("ttl", 0) and rec["ttl"] > 86400:
                issues.append(("High TTL", f"{rtype} {rec.get('value','')} TTL={rec['ttl']}"))
    return [(t, f, explanations.get(t, "")) for t, f in issues]

# ===== GUI Application =====
class DNSInspectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS & HTTP Inspector Pro")
        self.stop_refresh = threading.Event()

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        # --- DNS Tab ---
        self.dns_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dns_frame, text="DNS Inspector")
        self.setup_dns_tab()

        # --- Curl Tab ---
        self.curl_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.curl_frame, text="Curl Commands")
        self.setup_curl_tab()

    # --- DNS Tab UI ---
    def setup_dns_tab(self):
        frame_input = ttk.Frame(self.dns_frame)
        frame_input.pack(fill="x", padx=10, pady=5)
        ttk.Label(frame_input, text="Domain:").pack(side="left")
        self.domain_var = tk.StringVar()
        ttk.Entry(frame_input, textvariable=self.domain_var, width=30).pack(side="left", padx=5)
        ttk.Label(frame_input, text="Auto-refresh (sec):").pack(side="left", padx=5)
        self.refresh_var = tk.StringVar(value="0")
        ttk.Entry(frame_input, textvariable=self.refresh_var, width=5).pack(side="left")

        frame_opts = ttk.LabelFrame(self.dns_frame, text="Options")
        frame_opts.pack(fill="x", padx=10, pady=5)
        self.var_authoritative = tk.BooleanVar()
        ttk.Checkbutton(frame_opts, text="Query Authoritative", variable=self.var_authoritative).pack(side="left")
        self.var_diagnostics = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame_opts, text="Diagnostics", variable=self.var_diagnostics).pack(side="left")
        self.var_verbose = tk.BooleanVar()
        ttk.Checkbutton(frame_opts, text="Verbose", variable=self.var_verbose).pack(side="left")
        self.var_reverse = tk.BooleanVar()
        ttk.Checkbutton(frame_opts, text="Reverse Lookup", variable=self.var_reverse).pack(side="left")

        frame_records = ttk.LabelFrame(self.dns_frame, text="Record Types")
        frame_records.pack(fill="x", padx=10, pady=5)
        self.record_vars = {}
        for rtype in RECORD_TYPES:
            var = tk.BooleanVar(value=True)
            self.record_vars[rtype] = var
            ttk.Checkbutton(frame_records, text=rtype, variable=var).pack(side="left")

        frame_buttons = ttk.Frame(self.dns_frame)
        frame_buttons.pack(fill="x", padx=10, pady=5)
        ttk.Button(frame_buttons, text="Run", command=self.run_once).pack(side="left")
        ttk.Button(frame_buttons, text="Save Output", command=self.save_output).pack(side="left")
        ttk.Button(frame_buttons, text="Load Bulk Domains", command=self.load_bulk).pack(side="left")
        ttk.Button(frame_buttons, text="Stop Auto", command=self.stop_auto_refresh).pack(side="left")
        ttk.Button(frame_buttons, text="Clear Output", command=lambda: self.output.delete("1.0", tk.END)).pack(side="left")

        self.output = scrolledtext.ScrolledText(self.dns_frame, wrap="word", height=25)
        self.output.pack(fill="both", expand=True, padx=10, pady=5)

    # --- Curl Tab UI ---
    def setup_curl_tab(self):
        ttk.Label(self.curl_frame, text="URL:").pack(side="left", padx=5)
        self.curl_url_var = tk.StringVar()
        ttk.Entry(self.curl_frame, textvariable=self.curl_url_var, width=40).pack(side="left", padx=5)

        self.curl_flags_frame = ttk.LabelFrame(self.curl_frame, text="Flags")
        self.curl_flags_frame.pack(fill="x", padx=10, pady=5)
        self.curl_flags = {
            "-I": tk.BooleanVar(),
            "-L": tk.BooleanVar(),
            "-v": tk.BooleanVar(),
            "-s": tk.BooleanVar(),
            "--head": tk.BooleanVar(),
        }
        for flag, var in self.curl_flags.items():
            ttk.Checkbutton(self.curl_flags_frame, text=flag, variable=var).pack(side="left")

        ttk.Button(self.curl_frame, text="Run Curl", command=self.run_curl).pack(padx=5, pady=5)

        self.curl_output = scrolledtext.ScrolledText(self.curl_frame, wrap="word", height=25)
        self.curl_output.pack(fill="both", expand=True, padx=10, pady=5)

    # --- DNS Tab Methods ---
    def run_once(self):
        domain = self.domain_var.get().strip(".")
        if not domain:
            self.log("Enter a domain.\n", "error")
            return
        self.output.delete("1.0", tk.END)
        threading.Thread(target=self.run_inspection, args=(domain,), daemon=True).start()
        interval = int(self.refresh_var.get() or "0")
        if interval > 0:
            threading.Thread(target=self.auto_refresh, args=(domain, interval), daemon=True).start()

    def run_inspection(self, domain):
        self.log(f"=== DNS Inspection for {domain} ===\n\n", "header")
        resolver, ns_list = build_resolver(verbose=self.var_verbose.get())
        if self.var_authoritative.get():
            ns_hosts = get_authoritative_nameservers(domain)
            if ns_hosts:
                resolver.nameservers.clear()
                for ns in ns_hosts:
                    a_rec = query_record(build_resolver()[0], ns, "A")
                    if a_rec and "value" in a_rec[0]:
                        resolver.nameservers.append(a_rec[0]["value"])
                self.log(f"Using authoritative nameservers: {resolver.nameservers}\n")

        results = {}
        for rtype, var in self.record_vars.items():
            if var.get():
                if self.var_verbose.get():
                    self.log(f"Querying {rtype} for {domain}\n")
                results[rtype] = query_record(resolver, domain, rtype, verbose=self.var_verbose.get())
                for rec in results[rtype]:
                    if "error" in rec:
                        self.log(f"  ERROR: {rec['error']}\n", "error")
                    elif "value" in rec:
                        self.log(f"  TTL={rec.get('ttl')}  {rec['value']}\n")

        if self.var_reverse.get():
            ips = [r["value"] for r in results.get("A", []) if "value" in r]
            for ip in ips:
                try:
                    rev = dns.reversename.from_address(ip)
                    rev_result = resolver.resolve(rev, "PTR")
                    self.log(f"Reverse {ip} -> {rev_result[0]}\n", "section")
                except:
                    self.log(f"Reverse lookup failed for {ip}\n", "error")

        if self.var_diagnostics.get():
            self.log("\n=== Diagnostics ===\n", "header")
            for title, fix, expl in diagnostics(domain, results):
                self.log(f"- {title}: {fix}\nExplanation: {expl}\n\n", "warn")

    def auto_refresh(self, domain, interval):
        self.stop_refresh.clear()
        while not self.stop_refresh.is_set():
            self.output.delete("1.0", tk.END)
            self.run_inspection(domain)
            time.sleep(interval)

    def stop_auto_refresh(self):
        self.stop_refresh.set()

    def save_output(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path:
            with open(file_path, "w") as f:
                f.write(self.output.get("1.0", tk.END))
            self.log(f"Output saved to {file_path}\n", "ok")

    def load_bulk(self):
        file_path = filedialog.askopenfilename()
        if file_path and os.path.isfile(file_path):
            with open(file_path) as f:
                domains = [line.strip() for line in f if line.strip()]
            if domains:
                messagebox.showinfo("Bulk Domains Loaded", "\n".join(domains))
                self.domain_var.set("")  # clear input
                threading.Thread(target=self.run_bulk, args=(domains,), daemon=True).start()

    def run_bulk(self, domains):
        for domain in domains:
            self.log(f"\n=== Bulk: {domain} ===\n", "header")
            self.run_inspection(domain)

    # --- Curl Tab Methods ---
    def run_curl(self):
        url = self.curl_url_var.get().strip()
        if not url:
            messagebox.showerror("Error", "Enter a URL")
            return
        flags = [f for f, var in self.curl_flags.items() if var.get()]
        cmd = ["curl"] + flags + [url]
        self.curl_output.insert(tk.END, f"$ {' '.join(cmd)}\n", "header")
        self.curl_output.see(tk.END)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            self.curl_output.insert(tk.END, result.stdout + "\n")
            if result.stderr:
                self.curl_output.insert(tk.END, result.stderr + "\n", "error")
        except Exception as e:
            self.curl_output.insert(tk.END, f"Error: {e}\n", "error")
        self.curl_output.see(tk.END)

    # --- Utility ---
    def log(self, text, style=None):
        tag = None
        if style and style not in self.output.tag_names():
            colors = {"error":"red", "warn":"orange","ok":"green","header":"blue","section":"purple"}
            if style in colors:
                self.output.tag_configure(style, foreground=colors[style])
            tag = style
        elif style:
            tag = style
        self.output.insert(tk.END, text, tag)
        self.output.see(tk.END)

# ===== Main =====
if __name__ == "__main__":
    root = tk.Tk()
    app = DNSInspectorApp(root)
    root.mainloop()
