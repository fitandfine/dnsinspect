# DNS Inspector Pro - Enhanced Version

DNS Inspector Pro is a **user-friendly GUI tool** to inspect DNS records of any domain, perform automated diagnostics, and fetch real-time results. It is designed to help developers, system administrators, and IT professionals **quickly identify DNS issues** and gain insights into domain configurations.

---

## Features

- Inspect all major DNS record types: **A, AAAA, CNAME, MX, NS, SOA, TXT, CAA**.
- Check for **SPF, DMARC, and other important security records** automatically.
- Run **authoritative nameserver queries** for accurate results.
- **Bulk domain inspection** with live progress updates.
- Save results in **TXT or CSV** formats.
- Search and highlight text in the output window.
- Auto-refresh inspection for dynamic monitoring.
- Clear output button for clean workspace during multiple queries.
- Threaded execution ensures GUI **does not freeze during bulk queries**.

---

## Libraries Used

1. **Tkinter**
   - Provides the GUI framework including windows, frames, labels, buttons, checkboxes, and scrollable text.
   - Key components used:
     - `ttk.Frame`, `ttk.LabelFrame` for layout grouping.
     - `ttk.Entry` for user input.
     - `ttk.Checkbutton` to select options.
     - `ttk.Progressbar` for bulk query progress.
     - `scrolledtext.ScrolledText` for output display.
   
2. **dnspython**
   - Handles DNS queries and resolution.
   - Functions used:
     - `dns.resolver.Resolver()` to create a resolver instance.
     - `resolver.resolve(domain, rtype)` to query specific record types.
     - Exception handling for `NXDOMAIN`, `NoAnswer`, `LifetimeTimeout`.

3. **threading**
   - Allows **background execution** of DNS queries so the GUI remains responsive.
   - Each domain in bulk queries runs in its own thread.

4. **queue**
   - Thread-safe queue to pass bulk query results from threads to the GUI for live updates.

5. **time & os**
   - Handles sleep intervals for auto-refresh and file path checks.

6. **filedialog & messagebox**
   - Lets users select files for bulk queries and save outputs.
   - Provides interactive messages for warnings or confirmations.

---

## How It Works

1. **Input & Options**
   - User enters a domain name.
   - Choose record types to query.
   - Optionally enable:
     - **Authoritative querying**
     - **Diagnostics**
     - **Verbose output**

2. **Query Execution**
   - Uses `dns.resolver.Resolver()` to query the selected record types.
   - For each record, collects:
     - Record type
     - TTL
     - Value
   - Handles errors gracefully (`NXDOMAIN`, `Timeout`, `NoAnswer`).

3. **Diagnostics**
   - Analyzes results for common issues:
     - Missing apex A/AAAA records
     - MX host not resolving
     - Missing SPF/DMARC policies
     - Too few nameservers
     - High TTLs slowing propagation
   - Displays recommendations with explanations.

4. **Bulk Domain Support**
   - Reads domains from a file.
   - Runs each domain in a **separate thread**.
   - Updates results live in the GUI.
   - Progress bar shows completion percentage.

5. **Output Handling**
   - View results in a scrollable window.
   - Search for keywords in the output.
   - Save results as **TXT or CSV** for documentation or reporting.

6. **Auto-refresh**
   - Set a refresh interval to re-query domains automatically.
   - Useful for monitoring dynamic DNS changes.

---

