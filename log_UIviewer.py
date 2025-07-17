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

# --- Tag Colors ---
TAG_COLORS = {
    "Initial Access": "#e74c3c",
    "Execution": "#f39c12",
    "Persistence": "#8e44ad",
    "C2": "#3498db",
    "Exfiltration": "#2ecc71",
    "Cleanup": "#95a5a6",
    "": "#bdc3c7"  # Uncategorized
}

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
        "Tag", ["", "Initial Access", "Execution", "Persistence", "C2", "Exfiltration", "Cleanup"]
    )
    new_note = st.sidebar.text_area("Notes", value=selected_event.get("notes", ""))

    for i, evt in enumerate(st.session_state.event_store):
        if evt["uuid"] == selected_uuid:
            st.session_state.event_store[i]["tag"] = new_tag
            st.session_state.event_store[i]["notes"] = new_note
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
            if st.sidebar.button(f"Unhide {e['uuid']}", key=e['uuid']):
                st.session_state.excluded_uuids.remove(e['uuid'])

    # --- Graph Visualization ---
    st.subheader("\U0001f310 Process Relationship Graph")
    G = nx.DiGraph()

    for evt in visible_events:
        node_color = st.session_state.node_colors.get(evt["uuid"], TAG_COLORS[""])
        label = evt.get("Image", "Unknown")
        node_label = f"{label}\n{evt['tag'] or 'Uncategorized'}"
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

    def get_tag_emoji(tag):
        return {
            "Initial Access": "\U0001f6aa",
            "Execution": "💥",
            "Persistence": "\U0001f6e1️",
            "C2": "\U0001f4e1",
            "Exfiltration": "\U0001f4e4",
            "Cleanup": "\U0001f9f9",
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
        cmdline = node.get("CommandLine", "").strip()

        st.markdown(f"{prefix}{emoji}")
        indent = "&nbsp;&nbsp;&nbsp;" * (depth + 1)
        st.markdown(f"{indent}<code>{img}</code>", unsafe_allow_html=True)

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

        if cmdline:
            with st.expander("Show CommandLine", expanded=False):
                st.code(cmdline, language="bash")

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
