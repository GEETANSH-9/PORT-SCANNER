import streamlit as st
import pandas as pd
from portscanner import (
    threaded_scan,
    generate_report,
    validate_targets,
    save_scan,
    get_scan_history,
    get_scan_results,
    diff_scans,
    get_last_scan_id_for_target,
)


# CONFIG

DEFAULT_TARGET = "scanme.nmap.org"

st.set_page_config(page_title="Security Scanner", layout="wide")


# TITLE

st.title("🔐 Network Vulnerability Scanner")
st.markdown("Scan a system to detect open ports, services, vulnerabilities, and risk levels.")


# SIDEBAR — SCAN SETTINGS

st.sidebar.header("⚙️ Scan Settings")

choice = st.sidebar.radio("Choose Target", ["Use Nmap Test Server", "Enter Custom IP"])

if choice == "Enter Custom IP":
    targets_input = st.sidebar.text_area(
        "Enter IPs or hostnames (comma separated)",
        "scanme.nmap.org, 127.0.0.1"
    )
else:
    targets_input = DEFAULT_TARGET

# ── Upgrade 1: validate inputs before allowing scan ──
raw_targets = [t.strip() for t in targets_input.split(",") if t.strip()]
valid_targets, validation_errors = validate_targets(raw_targets)

if validation_errors:
    for err in validation_errors:
        st.sidebar.error(f"❌ {err}")

scan_disabled = len(valid_targets) == 0
scan = st.sidebar.button(
    "🚀 Start Scan",
    use_container_width=True,
    disabled=scan_disabled,
    help="Fix invalid targets above to enable scanning"
)

if valid_targets and valid_targets != raw_targets:
    st.sidebar.info(f"✅ Scanning {len(valid_targets)} valid target(s)")


# SESSION STATE

for key in ["results", "scan_diff", "current_scan_id"]:
    if key not in st.session_state:
        st.session_state[key] = None


# RUN SCAN

if scan and valid_targets:
    with st.spinner("Scanning in progress... ⏳"):
        try:
            results = threaded_scan(valid_targets)
            st.session_state["results"] = results

            # ── Upgrade 3: save to history + compute diff ──
            combined_target = ", ".join(valid_targets)
            old_scan_id = get_last_scan_id_for_target(combined_target)

            new_scan_id = save_scan(combined_target, results)
            st.session_state["current_scan_id"] = new_scan_id

            if old_scan_id:
                st.session_state["scan_diff"] = diff_scans(old_scan_id, results)
            else:
                st.session_state["scan_diff"] = None

        except Exception as e:
            st.error(f"❌ Scan failed: {e}")
            st.stop()


# TABS: Results | History

tab_results, tab_history = st.tabs(["📡 Scan Results", "🗂️ Scan History"])


# TAB 1 — RESULTS

with tab_results:
    if st.session_state["results"]:
        results = st.session_state["results"]

        # ── Upgrade 2: include CVSS column ──
        df = pd.DataFrame(results)[["Host", "Port", "Service", "Version", "CVE", "CVSS", "Risk"]]

        st.success("✅ Scan Completed")

        # ── Upgrade 3: diff banner ──
        diff = st.session_state.get("scan_diff")
        if diff:
            new_p  = diff["new_ports"]
            gone_p = diff["closed_ports"]
            chg_p  = diff["changed_ports"]

            if new_p or gone_p or chg_p:
                st.subheader("🔄 Changes Since Last Scan")
                c1, c2, c3 = st.columns(3)
                c1.metric("🆕 New ports opened", len(new_p))
                c2.metric("✅ Ports now closed", len(gone_p))
                c3.metric("⚡ Risk level changed", len(chg_p))

                if new_p:
                    st.error("**Newly opened ports:**")
                    st.dataframe(pd.DataFrame(new_p), use_container_width=True)

                if gone_p:
                    st.success("**Ports that are now closed (good news):**")
                    st.dataframe(pd.DataFrame(gone_p), use_container_width=True)

                if chg_p:
                    st.warning("**Risk level changes:**")
                    chg_rows = []
                    for c in chg_p:
                        chg_rows.append({
                            "Host":    c["new"]["Host"],
                            "Port":    c["new"]["Port"],
                            "Service": c["new"]["Service"],
                            "Old Risk": c["old"]["Risk"],
                            "New Risk": c["new"]["Risk"],
                        })
                    st.dataframe(pd.DataFrame(chg_rows), use_container_width=True)
            else:
                st.info("✅ No changes detected compared to the last scan.")

        # TABLE
        st.subheader("📊 Scan Results")
        st.dataframe(df, use_container_width=True)

        # SUMMARY METRICS
        total    = len(results)
        critical = sum(1 for r in results if "CRITICAL" in r["Risk"])
        high     = sum(1 for r in results if "HIGH"     in r["Risk"])
        avg_cvss = (
            sum(r["CVSS"] for r in results if r.get("CVSS", 0) > 0) /
            max(1, sum(1 for r in results if r.get("CVSS", 0) > 0))
        )

        st.subheader("📈 Summary")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Open Ports", total)
        col2.metric("Critical Risks",   critical)
        col3.metric("High Risks",       high)
        col4.metric("Avg CVSS Score",   f"{avg_cvss:.1f}")

        # RISK DISTRIBUTION CHART
        import matplotlib.pyplot as plt

        st.subheader("📊 Risk Distribution")
        if not df.empty:
            # Normalise risk labels for grouping (strip CVSS details)
            def risk_label(r):
                for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    if level in r:
                        return level
                return "LOW"

            df["Risk Level"] = df["Risk"].apply(risk_label)
            risk_counts = df["Risk Level"].value_counts()
            color_map = {
                "CRITICAL": "#E24B4A",
                "HIGH":     "#EF9F27",
                "MEDIUM":   "#378ADD",
                "LOW":      "#1D9E75",
            }
            colors = [color_map.get(l, "#888") for l in risk_counts.index]

            fig, ax = plt.subplots()
            ax.pie(risk_counts, labels=risk_counts.index, autopct="%1.1f%%", colors=colors)
            ax.set_title("Risk Distribution")
            st.pyplot(fig)

        # RISK ANALYSIS
        st.subheader("⚠️ Risk Analysis")
        for r in results:
            port = r["Port"]
            risk = r["Risk"]
            cvss = r.get("CVSS", 0)
            label = f"Port {port} ({r['Service']}) → {risk}"
            if cvss > 0:
                label += f"  |  CVE: {r['CVE']}"
            if "CRITICAL" in risk:
                st.error(f"🚨 {label}")
            elif "HIGH" in risk:
                st.warning(f"⚠️ {label}")
            elif "MEDIUM" in risk:
                st.info(f"ℹ️ {label}")

        # DOWNLOAD REPORT
        report_file = generate_report(results)
        with open(report_file, "rb") as f:
            st.download_button(
                label="📥 Download Scan Report (JSON)",
                data=f,
                file_name=report_file,
                mime="application/json"
            )

    else:
        st.info("👈 Select target(s) and click 'Start Scan' to begin.")


# TAB 2 — SCAN HISTORY

with tab_history:
    st.subheader("🗂️ Past Scans")

    history = get_scan_history(limit=30)

    if not history:
        st.info("No scan history yet. Run your first scan to start tracking.")
    else:
        history_df = pd.DataFrame(history)[["scan_id", "target", "scanned_at", "total_ports"]]
        history_df.columns = ["Scan ID", "Target", "Scanned At", "Open Ports Found"]
        st.dataframe(history_df, use_container_width=True)

        st.markdown("---")
        st.subheader("🔍 View a Past Scan")

        scan_ids   = [h["scan_id"] for h in history]
        scan_labels = {
            h["scan_id"]: f"#{h['scan_id']} — {h['target']} — {h['scanned_at'][:16]}"
            for h in history
        }

        selected_id = st.selectbox(
            "Select a scan to inspect",
            options=scan_ids,
            format_func=lambda x: scan_labels[x]
        )

        if selected_id:
            past_results = get_scan_results(selected_id)
            if past_results:
                past_df = pd.DataFrame(past_results)
                st.dataframe(past_df, use_container_width=True)

                # Compare two scans
                st.markdown("---")
                st.subheader("↔️ Compare Two Scans")

                if len(scan_ids) > 1:
                    compare_id = st.selectbox(
                        "Compare selected scan against:",
                        options=[s for s in scan_ids if s != selected_id],
                        format_func=lambda x: scan_labels[x]
                    )

                    if st.button("Run Comparison"):
                        compare_results = get_scan_results(selected_id)
                        delta = diff_scans(compare_id, compare_results)

                        c1, c2, c3 = st.columns(3)
                        c1.metric("New ports", len(delta["new_ports"]))
                        c2.metric("Closed ports", len(delta["closed_ports"]))
                        c3.metric("Risk changes", len(delta["changed_ports"]))

                        if delta["new_ports"]:
                            st.error("**New ports in selected scan:**")
                            st.dataframe(pd.DataFrame(delta["new_ports"]), use_container_width=True)
                        if delta["closed_ports"]:
                            st.success("**Ports closed in selected scan:**")
                            st.dataframe(pd.DataFrame(delta["closed_ports"]), use_container_width=True)
                        if not any([delta["new_ports"], delta["closed_ports"], delta["changed_ports"]]):
                            st.info("No differences found between the two scans.")
                else:
                    st.info("Scan at least two times to enable comparison.")
            else:
                st.warning("No results found for this scan ID.")