#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading, time, os, socket
import dns.resolver, dns.reversename
import requests, ssl, urllib3

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "CAA"]
EXTRA_CHECKS = ["_dmarc"]

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ===================== DNS Functions =====================
def build_resolver(server=None):
    resolver = dns.resolver.Resolver()
    if server:
        resolver.nameservers = [server]
    return resolver

def query_record(resolver, domain, rtype, verbose=False):
    results = []
    start = time.time()
    try:
        if verbose:
            results.append({"value": f"[VERBOSE] Querying {rtype} for {domain}"})
        answers = resolver.resolve(domain, rtype, raise_on_no_answer=False)
        ttl = answers.rrset.ttl if answers.rrset else None
        for rdata in answers:
            results.append({"type": rtype, "ttl": ttl, "value": str(rdata)})
        duration = round(time.time() - start, 3)
        if verbose:
            results.append({"value": f"[VERBOSE] {rtype} query took {duration}s, {len(answers)} records returned"})
    except dns.resolver.NoAnswer:
        results.append({"type": rtype, "error": "NoAnswer"})
    except dns.resolver.NXDOMAIN:
        results.append({"type": rtype, "error": "NXDOMAIN"})
    except dns.resolver.LifetimeTimeout:
        results.append({"type": rtype, "error": "Timeout"})
    except Exception as e:
        results.append({"type": rtype, "error": str(e)})
    return results

def diagnostics(domain, results):
    issues = []
    explanations = {
        "Missing apex A/AAAA": "No IP address records found for root domain. Add A or AAAA.",
        "Apex CNAME found": "CNAME at root breaks standards. Remove it.",
        "MX host unresolved": "Mail server host doesn't resolve. Add proper A/AAAA.",
        "Missing SPF": "No SPF record found. Add TXT with v=spf1.",
        "Missing DMARC": "No DMARC policy found. Add _dmarc TXT.",
        "Too few nameservers": "Less than 2 NS records. Add authoritative NS.",
        "NS host missing glue": "NS host doesn't resolve. Add A/AAAA.",
        "High TTL": "TTL > 1 day. Reduce TTL for faster propagation."
    }
    if not results.get("A") and not results.get("AAAA"):
        issues.append(("Missing apex A/AAAA", f"Add an A or AAAA record for {domain}"))
    if results.get("CNAME"):
        issues.append(("Apex CNAME found", "Avoid CNAME at apex"))
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
        issues.append(("Too few nameservers", "Add more NS records"))
    for rtype, recs in results.items():
        for rec in recs:
            if rec.get("ttl",0) and rec["ttl"]>86400:
                issues.append(("High TTL", f"{rtype} {rec.get('value','')} TTL={rec['ttl']}"))
    return [(t, f, explanations.get(t,"")) for t,f in issues]

# ===================== GUI App =====================
class DNSCurlApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS & HTTP Inspector Pro")
        self.stop_refresh = threading.Event()
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)
        self.setup_dns_tab()
        self.setup_curl_tab()

    # ================= DNS TAB =================
    def setup_dns_tab(self):
        self.dns_frame = ttk.Frame(self.notebook); self.notebook.add(self.dns_frame,text="DNS Inspector")
        frame_input = ttk.Frame(self.dns_frame); frame_input.pack(fill="x", padx=10,pady=5)
        ttk.Label(frame_input,text="Domain:").pack(side="left")
        self.domain_var = tk.StringVar(); ttk.Entry(frame_input,textvariable=self.domain_var,width=30).pack(side="left",padx=5)
        ttk.Label(frame_input,text="Auto-refresh (sec):").pack(side="left",padx=5)
        self.refresh_var = tk.StringVar(value="0"); ttk.Entry(frame_input,textvariable=self.refresh_var,width=5).pack(side="left")
        # Options
        frame_opts = ttk.LabelFrame(self.dns_frame,text="Options"); frame_opts.pack(fill="x", padx=10,pady=5)
        self.var_diagnostics = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame_opts,text="Diagnostics",variable=self.var_diagnostics).pack(side="left")
        self.var_verbose = tk.BooleanVar(); ttk.Checkbutton(frame_opts,text="Verbose",variable=self.var_verbose).pack(side="left")
        self.var_reverse = tk.BooleanVar(); ttk.Checkbutton(frame_opts,text="Reverse Lookup",variable=self.var_reverse).pack(side="left")
        # Record types
        frame_records = ttk.LabelFrame(self.dns_frame,text="Record Types"); frame_records.pack(fill="x", padx=10,pady=5)
        self.record_vars = {}
        for rtype in RECORD_TYPES:
            var = tk.BooleanVar(value=True); self.record_vars[rtype]=var
            ttk.Checkbutton(frame_records,text=rtype,variable=var).pack(side="left")
        # Buttons + Progress
        frame_btn = ttk.Frame(self.dns_frame); frame_btn.pack(fill="x", padx=10,pady=5)
        ttk.Button(frame_btn,text="Run",command=self.run_once).pack(side="left")
        ttk.Button(frame_btn,text="Save Output",command=self.save_output).pack(side="left")
        ttk.Button(frame_btn,text="Load Bulk Domains",command=self.load_bulk).pack(side="left")
        ttk.Button(frame_btn,text="Stop Auto",command=self.stop_auto_refresh).pack(side="left")
        ttk.Button(frame_btn,text="Clear Output",command=lambda:self.dns_output.delete("1.0",tk.END)).pack(side="left")
        self.progress = ttk.Progressbar(self.dns_frame,mode="determinate"); self.progress.pack(fill="x", padx=10, pady=2)
        # Output + Search
        frame_out = ttk.Frame(self.dns_frame); frame_out.pack(fill="both", expand=True)
        ttk.Label(frame_out,text="Search Output:").pack(side="top",anchor="w")
        search_frame = ttk.Frame(frame_out); search_frame.pack(fill="x")
        self.dns_search_var = tk.StringVar(); ttk.Entry(search_frame,textvariable=self.dns_search_var,width=20).pack(side="left")
        ttk.Button(search_frame,text="Find",command=self.search_dns).pack(side="left")
        self.dns_output = scrolledtext.ScrolledText(frame_out,wrap="word",height=25); self.dns_output.pack(fill="both",expand=True)

    # ================= CURL TAB =================
    def setup_curl_tab(self):
        self.curl_frame = ttk.Frame(self.notebook); self.notebook.add(self.curl_frame,text="HTTP Inspector")
        frame_input = ttk.LabelFrame(self.curl_frame,text="URL & Options"); frame_input.pack(fill="x", padx=10,pady=5)
        ttk.Label(frame_input,text="URL:").pack(side="left")
        self.curl_url_var = tk.StringVar(); ttk.Entry(frame_input,textvariable=self.curl_url_var,width=50).pack(side="left",padx=5)
        self.var_curl_diag = tk.BooleanVar(value=True); ttk.Checkbutton(frame_input,text="Diagnostics",variable=self.var_curl_diag).pack(side="left",padx=5)
        ttk.Button(frame_input,text="Run Request",command=self.run_curl).pack(side="left",padx=5)
        # Output + Search
        frame_out = ttk.Frame(self.curl_frame); frame_out.pack(fill="both", expand=True)
        ttk.Label(frame_out,text="Search Output:").pack(side="top",anchor="w")
        search_frame = ttk.Frame(frame_out); search_frame.pack(fill="x")
        self.curl_search_var=tk.StringVar(); ttk.Entry(search_frame,textvariable=self.curl_search_var,width=20).pack(side="left")
        ttk.Button(search_frame,text="Find",command=self.search_curl).pack(side="left")
        self.curl_output = scrolledtext.ScrolledText(frame_out,wrap="word",height=25); self.curl_output.pack(fill="both",expand=True)

    # ================= DNS Methods =================
    def run_once(self):
        domain = self.domain_var.get().strip(".")
        if not domain: messagebox.showerror("Error","Enter a domain"); return
        self.dns_output.delete("1.0",tk.END)
        threading.Thread(target=self.run_inspection,args=(domain,),daemon=True).start()
        interval = int(self.refresh_var.get() or "0")
        if interval>0: threading.Thread(target=self.auto_refresh,args=(domain,interval),daemon=True).start()

    def run_inspection(self,domain):
        resolver = build_resolver()
        self.log_dns(f"=== DNS Inspection: {domain} ===\n","header")
        selected_records = [r for r,v in self.record_vars.items() if v.get()]
        total = len(selected_records); self.progress["maximum"]=total; self.progress["value"]=0
        results = {}
        for rtype in selected_records:
            res=query_record(resolver,domain,rtype,verbose=self.var_verbose.get())
            results[rtype]=res
            for rec in res:
                if "error" in rec: self.log_dns(f"[{rtype}] ERROR: {rec['error']}\n","error")
                elif "value" in rec: self.log_dns(f"[{rtype}] TTL={rec.get('ttl')} {rec['value']}\n")
            self.progress["value"]+=1
        if self.var_reverse.get():
            ips=[r["value"] for r in results.get("A",[]) if "value" in r]
            for ip in ips:
                try:
                    ptr=dns.reversename.from_address(ip)
                    rev=query_record(resolver,str(ptr),"PTR")
                    if rev and "value" in rev[0]: self.log_dns(f"Reverse {ip} -> {rev[0]['value']}\n","section")
                except Exception as e: self.log_dns(f"Reverse lookup failed for {ip}: {e}\n","error")
        if self.var_diagnostics.get():
            diag=diagnostics(domain,results)
            self.log_dns("\n=== Diagnostics ===\n","header")
            for title, fix, expl in diag: self.log_dns(f"- {title}: {fix}\nExplanation: {expl}\n\n","warn")
        self.progress["value"]=0

    def auto_refresh(self,domain,interval):
        self.stop_refresh.clear()
        while not self.stop_refresh.is_set():
            time.sleep(interval)
            self.dns_output.delete("1.0",tk.END)
            self.run_inspection(domain)

    def stop_auto_refresh(self): self.stop_refresh.set()
    def save_output(self):
        file_path=filedialog.asksaveasfilename(defaultextension=".txt")
        if file_path: open(file_path,"w").write(self.dns_output.get("1.0",tk.END)); self.log_dns(f"Output saved to {file_path}\n","ok")
    def load_bulk(self):
        file_path=filedialog.askopenfilename()
        if file_path and os.path.isfile(file_path):
            domains=[line.strip() for line in open(file_path) if line.strip()]
            threading.Thread(target=self.run_bulk,args=(domains,),daemon=True).start()
    def run_bulk(self,domains):
        total=len(domains); self.progress["maximum"]=total; self.progress["value"]=0
        for domain in domains:
            self.log_dns(f"\n=== Bulk: {domain} ===\n","header")
            self.run_inspection(domain); self.progress["value"]+=1
        self.progress["value"]=0
    def search_dns(self):
        target=self.dns_search_var.get(); self.dns_output.tag_remove("search","1.0",tk.END)
        if target:
            idx="1.0"
            while True:
                idx=self.dns_output.search(target,idx,nocase=1,stopindex=tk.END)
                if not idx: break
                lastidx=f"{idx}+{len(target)}c"; self.dns_output.tag_add("search",idx,lastidx); idx=lastidx
            self.dns_output.tag_config("search",background="yellow",foreground="black")
    def log_dns(self,text,style=None):
        tag=None
        if style and style not in self.dns_output.tag_names():
            colors={"error":"red","warn":"orange","ok":"green","header":"blue","section":"purple"}
            if style in colors: self.dns_output.tag_configure(style,foreground=colors[style])
            tag=style
        elif style: tag=style
        self.dns_output.insert(tk.END,text,tag); self.dns_output.see(tk.END)

    # ================= CURL/HTTP Methods =================
    def run_curl(self):
        url = self.curl_url_var.get().strip()
        if not url: messagebox.showerror("Error","Enter a URL"); return
        self.curl_output.delete("1.0",tk.END)
        threading.Thread(target=self._run_curl_thread,args=(url,),daemon=True).start()

    def _run_curl_thread(self,url):
        self.curl_output.insert(tk.END,f"=== HTTP Request: {url} ===\n","header")
        try:
            start=time.time()
            resp = requests.get(url, verify=False, allow_redirects=True, timeout=20)
            duration = round(time.time()-start,3)
            # Headers
            self.curl_output.insert(tk.END,"\n--- Response Headers ---\n","header")
            for k,v in resp.headers.items():
                self.curl_output.insert(tk.END,f"{k}: {v}\n")
            # SSL info
            parsed_url = requests.utils.urlparse(url)
            if parsed_url.scheme=="https":
                hostname = parsed_url.hostname
                context = ssl.create_default_context()
                conn = context.wrap_socket(socket.socket(), server_hostname=hostname)
                conn.settimeout(5)
                conn.connect((hostname, 443))
                cert = conn.getpeercert()
                self.curl_output.insert(tk.END,"\n--- SSL Certificate Info ---\n","header")
                for k,v in cert.items():
                    self.curl_output.insert(tk.END,f"{k}: {v}\n")
                conn.close()
            # Redirects
            if resp.history:
                self.curl_output.insert(tk.END,"\n--- Redirect History ---\n","header")
                for r in resp.history: self.curl_output.insert(tk.END,f"{r.status_code} -> {r.url}\n")
            self.curl_output.insert(tk.END,f"\nFinal Status: {resp.status_code} ({resp.url})\n")
            self.curl_output.insert(tk.END,f"Total time: {duration}s\n","ok")
        except Exception as e:
            self.curl_output.insert(tk.END,f"Error: {e}\n","error")
        self.curl_output.see(tk.END)

    def search_curl(self):
        target=self.curl_search_var.get(); self.curl_output.tag_remove("search","1.0",tk.END)
        if target:
            idx="1.0"
            while True:
                idx=self.curl_output.search(target,idx,nocase=1,stopindex=tk.END)
                if not idx: break
                lastidx=f"{idx}+{len(target)}c"; self.curl_output.tag_add("search",idx,lastidx); idx=lastidx
            self.curl_output.tag_config("search",background="yellow",foreground="black")

# ===================== Main =====================
if __name__=="__main__":
    root=tk.Tk(); app=DNSCurlApp(root); root.mainloop()
