"""
Network Security Risk Dashboard — Data Analysis
=================================================
Author  : Harsha Narayan
Project : Network Security Risk Dashboard
Stack   : Python · Wireshark · SQL · Excel · Power BI

Analyst Narrative
-----------------
This project takes raw network traffic data (captured via Wireshark in a
controlled lab environment) and applies a structured data analysis workflow
to quantify security risk and support business decision-making.

The output is an executive Power BI dashboard with 5 KPI panels, making
complex security data accessible to non-technical stakeholders.

Workflow
--------
1. Parse and structure raw packet data (10,000+ simulated packets)
2. Load into SQL schema — query for vulnerability patterns
3. Build quantitative risk model (breach probability × cost)
4. Compare 2 mitigation strategies with NPV/payback
5. Export dashboard-ready datasets
6. Generate 5-panel analyst dashboard
"""

import os
import json
import warnings
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mtick
from matplotlib.gridspec import GridSpec
import sqlite3

warnings.filterwarnings("ignore")
os.makedirs("output", exist_ok=True)
os.makedirs("data", exist_ok=True)

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

# ═══════════════════════════════════════════════════════════════════════════════
# 1. SIMULATED PACKET DATA (mirrors Wireshark pcap capture)
#    In production: replace with pcap → pandas via pyshark
# ═══════════════════════════════════════════════════════════════════════════════
PROTOCOLS     = ["HTTP", "HTTPS", "ARP", "DNS", "TCP", "UDP", "ICMP"]
PROTO_WEIGHTS = [0.18, 0.35, 0.12, 0.12, 0.10, 0.08, 0.05]
VULN_TYPES    = ["ARP Spoof", "HTTP Credential", "DNS Poisoning",
                 "Session Hijack", "Port Scan", "None"]

def generate_packet_data(n: int = 10_000) -> pd.DataFrame:
    """Simulate 10,000 network packets captured in a 4-hour monitoring session."""
    timestamps = pd.date_range("2025-11-01 09:00", periods=n, freq="1.4s")
    protocols  = np.random.choice(PROTOCOLS, n, p=PROTO_WEIGHTS)
    src_ips    = [f"192.168.1.{np.random.randint(1, 121)}" for _ in range(n)]
    dst_ips    = [f"192.168.1.{np.random.randint(1, 121)}" for _ in range(n)]
    packet_len = np.random.lognormal(5.5, 1.2, n).clip(40, 65535).astype(int)
    ports      = np.random.choice([80, 443, 22, 3306, 8080, 53, 445, 8443,
                                    3389, 21, 25, 110], n)

    # Vulnerability detection (rule-based — mirrors Wireshark display filters)
    vuln = []
    for i in range(n):
        if protocols[i] == "ARP" and np.random.random() < 0.15:
            vuln.append("ARP Spoof")
        elif protocols[i] == "HTTP" and ports[i] == 80 and np.random.random() < 0.20:
            vuln.append("HTTP Credential")
        elif protocols[i] == "DNS" and np.random.random() < 0.05:
            vuln.append("DNS Poisoning")
        elif protocols[i] == "TCP" and ports[i] in [22, 3389] and np.random.random() < 0.08:
            vuln.append("Session Hijack")
        elif np.random.random() < 0.02:
            vuln.append("Port Scan")
        else:
            vuln.append("None")

    severity_map = {
        "ARP Spoof"        : "CRITICAL",
        "HTTP Credential"  : "CRITICAL",
        "DNS Poisoning"    : "HIGH",
        "Session Hijack"   : "HIGH",
        "Port Scan"        : "MEDIUM",
        "None"             : "LOW",
    }
    cvss_map = {
        "ARP Spoof": 8.1, "HTTP Credential": 9.1, "DNS Poisoning": 7.4,
        "Session Hijack": 7.5, "Port Scan": 4.0, "None": 0.0,
    }

    df = pd.DataFrame({
        "timestamp"      : timestamps,
        "protocol"       : protocols,
        "src_ip"         : src_ips,
        "dst_ip"         : dst_ips,
        "packet_length"  : packet_len,
        "port"           : ports,
        "vulnerability"  : vuln,
        "severity"       : [severity_map[v] for v in vuln],
        "cvss_score"     : [cvss_map[v] for v in vuln],
        "is_malicious"   : [1 if v != "None" else 0 for v in vuln],
    })
    return df


# ═══════════════════════════════════════════════════════════════════════════════
# 2. SQL SCHEMA + ANALYTICAL QUERIES
# ═══════════════════════════════════════════════════════════════════════════════
def load_to_sql(df: pd.DataFrame) -> sqlite3.Connection:
    conn = sqlite3.connect("data/network_traffic.db")
    df.to_sql("packets", conn, if_exists="replace", index=False)

    conn.execute("""
        CREATE VIEW IF NOT EXISTS vuln_summary AS
        SELECT vulnerability,
               severity,
               COUNT(*) AS packet_count,
               ROUND(AVG(cvss_score), 2) AS avg_cvss,
               ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM packets), 2) AS pct_of_traffic
        FROM packets
        WHERE vulnerability != 'None'
        GROUP BY vulnerability, severity
        ORDER BY avg_cvss DESC
    """)
    conn.execute("""
        CREATE VIEW IF NOT EXISTS top_source_ips AS
        SELECT src_ip,
               COUNT(*) AS malicious_packets,
               GROUP_CONCAT(DISTINCT vulnerability) AS attack_types
        FROM packets
        WHERE is_malicious = 1
        GROUP BY src_ip
        ORDER BY malicious_packets DESC
        LIMIT 20
    """)
    conn.execute("""
        CREATE VIEW IF NOT EXISTS protocol_risk AS
        SELECT protocol,
               COUNT(*) AS total_packets,
               SUM(is_malicious) AS malicious_packets,
               ROUND(100.0 * SUM(is_malicious) / COUNT(*), 2) AS malicious_rate_pct
        FROM packets
        GROUP BY protocol
        ORDER BY malicious_rate_pct DESC
    """)
    conn.commit()
    print(f"[SQL] {len(df):,} packets loaded. Views: vuln_summary, top_source_ips, protocol_risk")
    return conn


# ═══════════════════════════════════════════════════════════════════════════════
# 3. EDA + KEY FINDINGS
# ═══════════════════════════════════════════════════════════════════════════════
def run_eda(df: pd.DataFrame, conn: sqlite3.Connection):
    print("\n" + "═"*60)
    print("  NETWORK TRAFFIC EDA — KEY FINDINGS")
    print("═"*60)
    total      = len(df)
    malicious  = df["is_malicious"].sum()
    print(f"  Total packets analysed : {total:,}")
    print(f"  Malicious packets      : {malicious:,} ({malicious/total*100:.1f}%)")
    print(f"  Monitoring window      : {df['timestamp'].min()} – {df['timestamp'].max()}")

    print("\n  VULNERABILITY BREAKDOWN (SQL query):")
    vuln_df = pd.read_sql("SELECT * FROM vuln_summary", conn)
    print(vuln_df.to_string(index=False))

    print("\n  PROTOCOL RISK PROFILE (SQL query):")
    proto_df = pd.read_sql("SELECT * FROM protocol_risk", conn)
    print(proto_df.to_string(index=False))

    print("\n  TOP 5 SUSPICIOUS SOURCE IPs:")
    ip_df = pd.read_sql("SELECT * FROM top_source_ips LIMIT 5", conn)
    print(ip_df.to_string(index=False))

    critical = df[df["severity"] == "CRITICAL"]
    print(f"\n  CRITICAL vulnerabilities detected : {len(critical):,}")
    print(f"  Most frequent CRITICAL type       : {critical['vulnerability'].value_counts().idxmax()}")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. RISK QUANTIFICATION MODEL
# ═══════════════════════════════════════════════════════════════════════════════
RISK = {
    "annual_breach_probability_pct" : 34,
    "direct_breach_cost_lakh"       : 450,
    "credential_leak_lakh"          : 80,
    "regulatory_fine_lakh"          : 50,
    "reputational_loss_lakh"        : 120,
    "business_disruption_lakh"      : 35,
}
RISK["total_breach_cost_lakh"]   = sum(v for k, v in RISK.items() if "cost" in k or k.endswith("lakh"))
RISK["expected_annual_loss_lakh"]= round(RISK["total_breach_cost_lakh"] * RISK["annual_breach_probability_pct"] / 100, 1)

STRATEGIES = {
    "Status Quo"           : {"capex": 0,  "opex": 0,  "risk_red_pct": 0},
    "Strategy A (Port Sec)": {"capex": 8,  "opex": 2,  "risk_red_pct": 72},
    "Strategy B (ACL+IDS)" : {"capex": 28, "opex": 7,  "risk_red_pct": 91},
}

def compute_npv(s: dict, years: int = 5, r: float = 0.10) -> dict:
    ann_save = RISK["total_breach_cost_lakh"] * RISK["annual_breach_probability_pct"] / 100 * s["risk_red_pct"] / 100
    ann_net  = ann_save - s["opex"]
    cfs      = [-s["capex"]] + [ann_net] * years
    npv      = sum(cf / (1+r)**t for t, cf in enumerate(cfs))
    cum, pb  = -s["capex"], None
    for yr in range(1, years+1):
        cum += ann_net
        if cum >= 0 and pb is None:
            pb = round(yr - 1 + (s["capex"] - sum([ann_net]*max(yr-1,0))) / (ann_net + 1e-9), 1)
    return {"annual_saving": round(ann_save,1), "npv_5yr": round(npv,1), "payback_yr": pb}


# ═══════════════════════════════════════════════════════════════════════════════
# 5. VISUALISATIONS — 5-PANEL ANALYST DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
def generate_dashboard(df: pd.DataFrame, conn: sqlite3.Connection):
    TEAL  = "#0B5394"
    RED   = "#C0392B"
    ORG   = "#E67E22"
    GREEN = "#1E8449"
    BG    = "#F7F9FC"

    fig = plt.figure(figsize=(18, 11), facecolor=BG)
    gs  = GridSpec(2, 3, figure=fig, hspace=0.50, wspace=0.38)

    # Chart 1: Vulnerability frequency
    ax1 = fig.add_subplot(gs[0, 0])
    v_counts = df[df["vulnerability"]!="None"]["vulnerability"].value_counts()
    colors_v = [RED if "ARP" in v or "Cred" in v else ORG if "DNS" in v or "Hijack" in v
                else TEAL for v in v_counts.index]
    ax1.barh(v_counts.index, v_counts.values, color=colors_v, edgecolor="white", linewidth=1.1)
    ax1.set_title("Vulnerability Frequency\n(10K packets)", fontweight="bold", color=TEAL, fontsize=11)
    ax1.set_xlabel("Packet Count", fontsize=9)
    for i, v in enumerate(v_counts.values):
        ax1.text(v + 3, i, str(v), va="center", fontsize=8, fontweight="bold")
    ax1.set_facecolor(BG)

    # Chart 2: Protocol risk profile
    ax2 = fig.add_subplot(gs[0, 1])
    proto_df = pd.read_sql("SELECT protocol, malicious_rate_pct FROM protocol_risk", conn)
    bars2 = ax2.bar(proto_df["protocol"], proto_df["malicious_rate_pct"],
                    color=TEAL, alpha=0.85, edgecolor="white")
    ax2.set_title("Malicious Packet Rate by Protocol (%)", fontweight="bold", color=TEAL, fontsize=11)
    ax2.yaxis.set_major_formatter(mtick.PercentFormatter())
    ax2.set_facecolor(BG)
    plt.setp(ax2.get_xticklabels(), rotation=20, ha="right", fontsize=8)

    # Chart 3: Severity distribution pie
    ax3 = fig.add_subplot(gs[0, 2])
    sev_counts = df[df["is_malicious"]==1]["severity"].value_counts()
    colors_pie = {"CRITICAL": RED, "HIGH": ORG, "MEDIUM": "#F1C40F", "LOW": GREEN}
    ax3.pie(sev_counts.values, labels=sev_counts.index,
            colors=[colors_pie.get(s, TEAL) for s in sev_counts.index],
            autopct="%1.0f%%", textprops={"fontsize": 9}, startangle=90)
    ax3.set_title(f"Threat Severity Distribution\n({sev_counts.sum():,} malicious events)",
                  fontweight="bold", color=TEAL, fontsize=11)

    # Chart 4: Attack timeline (hourly)
    ax4 = fig.add_subplot(gs[1, :2])
    df_mal = df[df["is_malicious"]==1].copy()
    df_mal["hour"] = df_mal["timestamp"].dt.floor("30min")
    timeline = df_mal.groupby(["hour","severity"]).size().unstack(fill_value=0)
    for sev, color in [("CRITICAL", RED), ("HIGH", ORG), ("MEDIUM", "#F1C40F")]:
        if sev in timeline.columns:
            ax4.fill_between(timeline.index, timeline[sev], alpha=0.7, color=color, label=sev)
    ax4.set_title("Malicious Event Timeline (30-min buckets)", fontweight="bold", color=TEAL, fontsize=11)
    ax4.set_xlabel("Time", fontsize=9)
    ax4.set_ylabel("Event Count", fontsize=9)
    ax4.legend(fontsize=9)
    ax4.set_facecolor(BG)
    plt.setp(ax4.get_xticklabels(), rotation=20, ha="right", fontsize=7)

    # Chart 5: NPV comparison
    ax5 = fig.add_subplot(gs[1, 2])
    fin_data = {name: compute_npv(s) for name, s in STRATEGIES.items()}
    npvs  = [fin_data[n]["npv_5yr"] for n in STRATEGIES]
    names = list(STRATEGIES.keys())
    bar_colors = [RED, GREEN, TEAL]
    bars5 = ax5.bar(names, npvs, color=bar_colors, edgecolor="white", linewidth=1.2)
    ax5.axhline(0, color="black", linewidth=0.8)
    ax5.set_title("5-Year NPV by Mitigation\nStrategy (₹L)", fontweight="bold", color=TEAL, fontsize=11)
    ax5.set_ylabel("₹ Lakh", fontsize=9)
    for b, v in zip(bars5, npvs):
        ax5.text(b.get_x() + b.get_width()/2, v + (5 if v >= 0 else -15),
                 f"₹{v}L", ha="center", fontsize=8, fontweight="bold",
                 color="green" if v >= 0 else "red")
    ax5.set_facecolor(BG)
    plt.setp(ax5.get_xticklabels(), rotation=15, ha="right", fontsize=7)

    fig.suptitle("Network Security Risk Dashboard — Analyst View | 10,000 Packets × 4-Hour Session",
                 fontsize=13, fontweight="bold", color=TEAL, y=1.01)
    plt.savefig("output/security_analyst_dashboard.png", dpi=150, bbox_inches="tight", facecolor=BG)
    print("[Chart] Saved → output/security_analyst_dashboard.png")
    plt.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 6. EXPORT
# ═══════════════════════════════════════════════════════════════════════════════
def export_data(df: pd.DataFrame, conn: sqlite3.Connection):
    # Full packet log
    df.to_csv("output/packet_log.csv", index=False)

    # Vulnerability summary
    pd.read_sql("SELECT * FROM vuln_summary", conn).to_csv("output/vuln_summary.csv", index=False)
    pd.read_sql("SELECT * FROM protocol_risk", conn).to_csv("output/protocol_risk.csv", index=False)

    # Risk model
    fin_rows = []
    for name, s in STRATEGIES.items():
        fin = compute_npv(s)
        fin_rows.append({"strategy": name, **s, **fin,
                          "expected_annual_loss_lakh": RISK["expected_annual_loss_lakh"]})
    pd.DataFrame(fin_rows).to_csv("output/risk_model.csv", index=False)

    print("[Export] CSVs saved: packet_log, vuln_summary, protocol_risk, risk_model")
    print("         → Connect Power BI to output/ folder for live dashboard")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("[1/5] Generating 10,000 network packet records...")
    df = generate_packet_data(10_000)
    df.to_csv("data/packet_capture.csv", index=False)

    print("[2/5] Loading to SQL + creating analytical views...")
    conn = load_to_sql(df)

    print("[3/5] Running EDA + key findings...")
    run_eda(df, conn)

    print("\n[4/5] Generating 5-panel analyst dashboard...")
    generate_dashboard(df, conn)

    print("[5/5] Exporting CSVs for Power BI / Tableau...")
    export_data(df, conn)

    print("\n" + "═"*55)
    print("  RISK SUMMARY")
    print("═"*55)
    print(f"  Expected Annual Loss       : ₹{RISK['expected_annual_loss_lakh']}L")
    for name, s in STRATEGIES.items():
        fin = compute_npv(s)
        pb  = f"{fin['payback_yr']}yr" if fin["payback_yr"] else "Never"
        print(f"  {name:<26} NPV: ₹{fin['npv_5yr']:>6}L | Payback: {pb}")
    print("═"*55)
    print("\n[Done] All outputs in /output/")
