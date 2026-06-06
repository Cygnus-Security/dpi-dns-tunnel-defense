import streamlit as st
import json
import pandas as pd
import time
import os
import altair as alt

# Configure wide layout for the security monitoring dashboard
st.set_page_config(
    page_title="IDPS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# Set main dashboard header
st.title("🛡️ Real-Time DNS Tunneling Detection & Prevention System")
st.markdown("---")

TELEMETRY_FILE = "dns_telemetry.json"

def load_telemetry():
    """Read live telemetry data exported by the backend parsing engine"""
    if not os.path.exists(TELEMETRY_FILE):
        return {"blocked_ips": [], "volume_quota": {}, "last_updated": "N/A"}
    try:
        with open(TELEMETRY_FILE, "r") as f:
            return json.load(f)
    except:
        return {"blocked_ips": [], "volume_quota": {}, "last_updated": "N/A"}

# --- FETCH LIVE TELEMETRY DATA ---
data = load_telemetry()

# ==========================================
# SECTION 1: KPI METRICS CARDS
# ==========================================
col1, col2, col3 = st.columns(3)

with col1:
    total_blocked = len(data["blocked_ips"])
    st.metric(
        label="🚨 Currently Isolated IPs", 
        value=total_blocked,
        delta=f"+{total_blocked} Active Threats" if total_blocked > 0 else "Network Secure",
        delta_color="inverse"
    )

with col2:
    # Calculate the total accumulated bytes across all tracked anomalies
    total_bytes = sum(data["volume_quota"].values())
    st.metric(
        label="📊 Total Cumulative Payload Volume (Bytes)", 
        value=f"{total_bytes} B",
        delta="30s Sliding Window"
    )

with col3:
    st.metric(
        label="🕒 Last System Sync Time", 
        value=data["last_updated"]
    )

st.markdown("---")

# ==========================================
# SECTION 2: GRAPH & DATA VISUALIZATION
# ==========================================
left_chart_col, right_table_col = st.columns([2, 1])

with left_chart_col:
    st.subheader("📈 Data Exfiltration Volume by Host Source")
    
    if data["volume_quota"]:
        # Convert raw telemetry data into a Pandas DataFrame for mapping
        quota_df = pd.DataFrame(
            list(data["volume_quota"].items()), 
            columns=["Entity (IP ➔ Target Domain)", "Volume (Bytes)"]
        )
        
        # Map the static mitigation limit (1000 Bytes as configured in backend thresholds)
        quota_df["Threshold Limit"] = 1000
        
        # Extract the source host IP from the "Entity (IP ➔ Target Domain)" string for clearer visualization
        quota_df["Source Host IP"] = quota_df["Entity (IP ➔ Target Domain)"].apply(lambda x: x.split(" ➔ ")[0])
        
        # Render the interactive bar chart using Altair for better customization and interactivity
        chart = alt.Chart(quota_df).mark_bar(color="#1f77b4", size=40).encode(
            x=alt.X("Source Host IP:N", axis=alt.Axis(labelAngle=0, title="Source IP Address")),
            y=alt.Y("Volume (Bytes):Q", title="Volume (Bytes)")
        ).properties(
            height=400
        )
        
        # Use Streamlit's Altair integration to display the chart with responsive width
        st.altair_chart(chart, width='stretch')
        
    else:
        st.info("No anomalous data exfiltration or threshold-breaching traffic detected.")

with right_table_col:
    st.subheader("🚫 Active Network Blocklist")
    if data["blocked_ips"]:
        blocked_df = pd.DataFrame(data["blocked_ips"], columns=["Compromised Host IP Address"])
        # Render the isolated hosts database table
        st.dataframe(blocked_df, width='stretch')
        st.error("Critical Alert: Kernel-level iptables DROP chains are active for the isolated hosts above.")
    else:
        st.success("Internal perimeter is clean. No hosts are currently quarantined.")

# ==========================================
# SECTION 3: AUTOMATED REFRESH MECHANISM
# ==========================================
# Force Streamlit UI to re-run every 1 second to fetch live updates without polling lag
time.sleep(1)
st.rerun()