import streamlit as st
import pandas as pd
import json
import uuid
import networkx as nx
from pyvis.network import Network
import tempfile
import os
from collections import defaultdict

st.set_page_config(layout="wide")
st.title("\U0001f575️ EVTX Threat Hunting UI")

# --- Session State Init ---
if "event_store" not in st.session_state:
    st.session_state.event_store = []
if "node_colors" not in st.session_state:
    st.session_state.node_colors = {}
if "excluded_uuids" not in st.session_state:
    st.session_state.excluded_uuids = set()
if "fields_to_show_per_event" not in st.session_state:
    st.session_state.fields_to_show_per_event = {}

# --- Tag Colors ---
TAG_COLORS = {
    "Initial Access": "#e74c3c",
    "Execution": "#f39c12",
    "Persistence": "#8e44ad",
    "C2": "#3498db",
    "Exfiltration": "#2ecc71",
    "Cleanup": "#95a5a6",
    "Enumeration": "#2980b9",
    "Discovery": "#f1c40f",
    "": "#bdc3c7"  # Uncategorized
}

# ====== MITRE ATT&CK HARD-CODED DICTIONARY ======
MITRE_TECHNIQUES = {
    "": {"name": "", "url": ""},
    "T1059": {"name": "Command and Scripting Interpreter", "url": "https://attack.mitre.org/techniques/T1059/"},
    "T1086": {"name": "PowerShell", "url": "https://attack.mitre.org/techniques/T1086/"},
    "T1569": {"name": "System Services", "url": "https://attack.mitre.org/techniques/T1569/"},
    "T1027": {"name": "Obfuscated Files or Information", "url": "https://attack.mitre.org/techniques/T1027/"},
    "T1204": {"name": "User Execution", "url": "https://attack.mitre.org/techniques/T1204/"},
    "T1105": {"name": "Ingress Tool Transfer", "url": "https://attack.mitre.org/techniques/T1105/"},
    "T1003": {"name": "OS Credential Dumping", "url": "https://attack.mitre.org/techniques/T1003/"},
    "T1218": {"name": "Signed Binary Proxy Execution", "url": "https://attack.mitre.org/techniques/T1218/"},
    "T1047": {"name": "Windows Management Instrumentation", "url": "https://attack.mitre.org/techniques/T1047/"},
    "TA0010 Exfiltration": {"name": "Exfiltration", "url": "https://attack.mitre.org/tactics/TA0010/"},
    "T1033 System Owner/User Discovery": {"name": "System Owner/User Discovery", "url": "https://attack.mitre.org/techniques/T1033/"},
    "T1082 System Information Discovery": {"name": "System Information Discovery", "url": "https://attack.mitre.org/techniques/T1082/"},
    "T1047 Windows Management Instrumentation": {"name": "Windows Management Instrumentation", "url": "https://attack.mitre.org/techniques/T1047/"},
    "T1057 Process Discovery": {"name": "Process Discovery", "url": "https://attack.mitre.org/techniques/T1057/"},
    "T1074 Data Staged": {"name": "Data Staged", "url": "https://attack.mitre.org/techniques/T1074/"},
    "T1059 Command and Scripting Interpreter: PowerShell": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
}
# ================================================

# --- File Upload ---
st.sidebar.header("\U0001f4c2 Upload Logs")
uploaded_files = st.sidebar.file_uploader(
    "Upload one or more EVTX-converted JSON files",
    type=["json"],
    accept_multiple_files=True,
)

# --- Parse JSON Function ---
def parse_json(file):
    data = json.load(file)
    if isinstance(data, dict):
        data = [data]

    parsed_events = []
    for evt in data:
        flat = {k: v for k, v in evt.items() if k != "DataValues"}
        for item in evt.get("DataValues", []):
            flat[item["Name"]] = item["Value"]
        flat["uuid"] = str(uuid.uuid4())
        flat["tag"] = ""
        flat["notes"] = ""
        flat["mitre"] = ""  # <-- Initialize mitre field here
        parsed_events.append(flat)
    return parsed_events

# --- Load Uploaded Events ---
if uploaded_files:
    for f in uploaded_files:
        new_events = parse_json(f)
        existing_keys = {(e.get("ProcessGuid"), e.get("UtcTime")) for e in st.session_state.event_store}
        for evt in new_events:
            key = (evt.get("ProcessGuid"), evt.get("UtcTime"))
            if key not in existing_keys:
                st.session_state.event_store.append(evt)
                st.session_state.node_colors[evt["uuid"]] = TAG_COLORS[""]

# --- Filter out hidden events ---
visible_events = [e for e in st.session_state.event_store if e["uuid"] not in st.session_state.excluded_uuids]
df = pd.DataFrame(visible_events)

if not df.empty:
    with st.expander("\U0001f50d Event Table (click to expand)", expanded=True):
        visible_columns = sorted(set().union(*[e.keys() for e in visible_events]))
        df_full = df.reindex(columns=visible_columns)
        df_full["UtcTime"] = pd.to_datetime(df_full["UtcTime"], errors="coerce")
        df_full = df_full.sort_values("UtcTime")
        st.dataframe(df_full, use_container_width=True)

    # --- Annotate Events ---
    st.sidebar.header("✏️ Annotate Events")
    selected_uuid = st.sidebar.selectbox("Select Event by UUID", df["uuid"])
    selected_event = df[df["uuid"] == selected_uuid].iloc[0]

    st.sidebar.write(f"**Image:** {selected_event.get('Image', 'N/A')}")
    new_tag = st.sidebar.selectbox(
        "Tag",
        [
            "",
            "Initial Access",
            "Execution",
            "Persistence",
            "C2",
            "Exfiltration",
            "Cleanup",
            "Enumeration",
            "Discovery",
            "Collection"
        ],
    )
    new_note = st.sidebar.text_area("Notes", value=selected_event.get("notes", ""))

    # ======= MITRE Technique Selection Dropdown =======
    mitre_ids = sorted(MITRE_TECHNIQUES.keys())
    selected_mitre = st.sidebar.selectbox(
        "MITRE Technique ID",
        mitre_ids,
        index=mitre_ids.index(selected_event.get("mitre", "") if selected_event.get("mitre", "") in mitre_ids else ""),
    )
    if selected_mitre:
        mitre_info = MITRE_TECHNIQUES.get(selected_mitre, {"name": "", "url": ""})
        if mitre_info["name"]:
            st.sidebar.markdown(f"[{mitre_info['name']}]({mitre_info['url']})", unsafe_allow_html=True)
    # ===================================================

    for i, evt in enumerate(st.session_state.event_store):
        if evt["uuid"] == selected_uuid:
            st.session_state.event_store[i]["tag"] = new_tag
            st.session_state.event_store[i]["notes"] = new_note
            st.session_state.event_store[i]["mitre"] = selected_mitre  # <-- Store MITRE ID here
            st.session_state.node_colors[selected_uuid] = TAG_COLORS.get(new_tag, TAG_COLORS[""])
            break

    is_excluded = selected_uuid in st.session_state.excluded_uuids
    if st.sidebar.button("🚫 Hide this log from view" if not is_excluded else "♻️ Unhide this log"):
        if is_excluded:
            st.session_state.excluded_uuids.remove(selected_uuid)
        else:
            st.session_state.excluded_uuids.add(selected_uuid)

    if st.sidebar.checkbox("Show hidden logs"):
        hidden_events = [e for e in st.session_state.event_store if e["uuid"] in st.session_state.excluded_uuids]
        st.sidebar.write(f"Total hidden: {len(hidden_events)}")
        for e in hidden_events:
            st.sidebar.markdown(f"- `{e['uuid']}` | **{e.get('Image', 'N/A')}**")
            if st.sidebar.button(f"Unhide {e['uuid']}", key=e["uuid"]):
                st.session_state.excluded_uuids.remove(e["uuid"])

    # --- Graph Visualization ---
    st.subheader("\U0001f310 Process Relationship Graph")
    G = nx.DiGraph()

    for evt in visible_events:
        node_color = st.session_state.node_colors.get(evt["uuid"], TAG_COLORS[""])
        label = evt.get("Image", "Unknown")
        mitre_id = evt.get("mitre", "")
        mitre_info = MITRE_TECHNIQUES.get(mitre_id, {})
        node_label = f"{label}\n{evt['tag'] or 'Uncategorized'}"
        if mitre_id:
            node_label += f"\n{mitre_id}: {mitre_info.get('name', '')}"
        G.add_node(evt["uuid"], label=node_label, color=node_color)

    for evt in visible_events:
        parent_guid = evt.get("ParentProcessGuid")
        child_guid = evt.get("ProcessGuid")
        if parent_guid and child_guid:
            parent = next((e for e in visible_events if e.get("ProcessGuid") == parent_guid), None)
            if parent:
                G.add_edge(parent["uuid"], evt["uuid"])

    net = Network(height="600px", width="100%", directed=True)
    net.from_nx(G)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_file:
        net.save_graph(tmp_file.name)
        st.components.v1.html(open(tmp_file.name, "r", encoding="utf-8").read(), height=600)
        os.unlink(tmp_file.name)

    # --- Execution Flow Timeline (Tree View) ---
    st.subheader("\U0001f9ec Execution Flow Timeline (Tree View)")

    show_untagged = st.sidebar.checkbox("Show untagged events", value=True)

    guid_to_event = {e.get("ProcessGuid"): e for e in visible_events}
    child_map = defaultdict(list)
    for e in visible_events:
        parent_guid = e.get("ParentProcessGuid")
        if parent_guid:
            child_map[parent_guid].append(e)

    # --- All keys & default fields for selection ---
    all_keys = sorted(set().union(*[e.keys() for e in visible_events])) if visible_events else []
    default_fields = ["CommandLine", "User", "IntegrityLevel", "ProcessId", "EventID"]

    # --- Move multiselect widgets outside recursion: per-event in sidebar ---
    st.sidebar.header("Select Fields Per Event")
    for evt in visible_events:
        event_id = evt["uuid"]
        if event_id not in st.session_state.fields_to_show_per_event:
            st.session_state.fields_to_show_per_event[event_id] = [f for f in default_fields if f in all_keys]

        selected_fields = st.sidebar.multiselect(
            f"Fields for event {event_id} ({evt.get('Image', 'Unknown')})",
            options=all_keys,
            default=st.session_state.fields_to_show_per_event[event_id],
            key=f"fields_{event_id}",
        )
        st.session_state.fields_to_show_per_event[event_id] = selected_fields

    def get_tag_emoji(tag):
        return {
            "Initial Access": "\U0001f6aa",
            "Execution": "💥",
            "Persistence": "\U0001f6e1️",
            "C2": "\U0001f4e1",
            "Exfiltration": "\U0001f4e4",
            "Enumeration": "🔍",
            "Discovery": "💡",
            "Cleanup": "\U0001f9f9",
            "Collection": "🗃️",
            "": "\U0001f9e9",
        }.get(tag, "\U0001f9e9")

    def get_tag_color(tag):
        return TAG_COLORS.get(tag, "#bdc3c7")

    def format_tree_line(depth, is_last, sibling_stack):
        prefix = ""
        for i in range(depth - 1):
            prefix += "│   " if sibling_stack[i] else "    "
        prefix += "└── " if is_last else "├── "
        return prefix

    def display_tree(node, child_map, depth=0, sibling_stack=[]):
        if node is None:
            return

        tag = node.get("tag", "")
        if not show_untagged and tag == "":
            return

        children = sorted(child_map.get(node.get("ProcessGuid"), []), key=lambda e: e.get("UtcTime", ""))
        is_last = True if not sibling_stack else not sibling_stack[-1]

        prefix = format_tree_line(depth, is_last, sibling_stack)
        emoji = get_tag_emoji(tag)
        color = get_tag_color(tag)
        img = node.get("Image", "Unknown")
        time = node.get("UtcTime", "")
        uuid_val = node.get("uuid", "")

        st.markdown(f"{prefix}{emoji}")
        indent = "&nbsp;&nbsp;&nbsp;" * (depth + 1)
        st.markdown(
            f"{indent}<code>{img}</code> <span style='color:#888; font-family: monospace;'>[{uuid_val}]</span>",
            unsafe_allow_html=True,
        )

        if tag:
            st.markdown(
                f"{indent}<span style='color:{color}; font-style: italic; font-weight: 600;'>`{tag}`  \U0001f552 *{time}*</span>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"{indent}<span style='color:gray; font-style: italic;'>\U0001f9e9 [Uncategorized] \U0001f552 *{time}*</span>",
                unsafe_allow_html=True,
            )

        # ======= MITRE Display in Tree View =======
        mitre_id = node.get("mitre", "")
        if mitre_id in MITRE_TECHNIQUES and mitre_id != "":
            mitre_info = MITRE_TECHNIQUES[mitre_id]
            st.markdown(
                f"{indent}🧩 <a href='{mitre_info['url']}' target='_blank'><code>{mitre_id}</code> - {mitre_info['name']}</a>",
                unsafe_allow_html=True,
            )
        # ==========================================

        # Get the selected fields for this event from session state (no widgets here!)
        selected_fields = st.session_state.fields_to_show_per_event.get(uuid_val, [])

        # Show selected fields with expanders (except CommandLine, which gets special code formatting)
        for field in selected_fields:
            if field == "CommandLine":
                cmdline = node.get("CommandLine", "").strip()
                if cmdline:
                    with st.expander("Show CommandLine", expanded=False):
                        st.code(cmdline, language="bash")
            else:
                val = node.get(field, "")
                if val:
                    with st.expander(f"Show {field}", expanded=False):
                        st.write(val)

        for idx, child in enumerate(children):
            has_siblings_below = idx < len(children) - 1
            display_tree(child, child_map, depth + 1, sibling_stack + [has_siblings_below])

    roots = [e for e in visible_events if e.get("ParentProcessGuid") not in guid_to_event]
    roots_sorted = sorted(roots, key=lambda e: e.get("UtcTime", ""))

    for root in roots_sorted:
        display_tree(root, child_map)

    # --- Export Annotated Logs ---
    st.sidebar.markdown("---")
    if st.sidebar.button("\U0001f4e4 Export Annotated Logs"):
        out_df = pd.DataFrame(st.session_state.event_store)
        st.sidebar.download_button(
            "Download JSON",
            data=out_df.to_json(orient="records", indent=2),
            file_name="annotated_logs.json",
        )
        st.sidebar.download_button(
            "Download CSV",
            data=out_df.to_csv(index=False),
            file_name="annotated_logs.csv",
        )
else:
    st.info("Upload EVTX JSON files to start hunting.")
