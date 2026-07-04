import streamlit as st
from collections import defaultdict

st.set_page_config(page_title="Multi-Client IOC Generator", layout="wide")
st.title("🛡️ SOC Hunting: Multi-Client AQL Generator")

client = st.selectbox("Select Client", ["Tarshid", "Alraedah"])
uploaded_file = st.file_uploader("Upload your IOC file (Format: value,label)", type=['csv', 'txt'])

# --- DYNAMIC MAPPING CONFIGURATION ---
# Add any new labels here. 
# 'col': The field name in the database
# 'cat': The category name for the 'IOC-HUNT-' string
# 'is_ilike': True for string search, False for IN list search
CONFIG = {
    'domain': {'col': 'URL HOST', 'cat': 'Domain', 'is_ilike': True},
    'fqdn':   {'col': 'URL HOST', 'cat': 'Domain', 'is_ilike': True},
    'url':    {'col': 'URL', 'cat': 'URL', 'is_ilike': True},
    'mailsender': {'col': 'sender', 'cat': 'MailSender', 'is_ilike': True},
    'subject':    {'col': 'subject', 'cat': 'MailSubject', 'is_ilike': True},
    'md5':        {'col': 'MD5 Hash', 'cat': 'MD5', 'is_ilike': False},
    'sha256':     {'col': 'SHA256 Hash', 'cat': 'SHA256', 'is_ilike': False},
    'sha1':       {'col': 'SHA1 Hash', 'cat': 'SHA1', 'is_ilike': False},
    'ip':         {'col': 'sourceIP', 'cat': 'IP', 'is_ilike': False},
    'file':       {'col': 'Filename', 'cat': 'FileArtifacts', 'is_ilike': False},
    'filename':   {'col': 'Filename', 'cat': 'FileArtifacts', 'is_ilike': False}
}

def get_chunks(conditions, limit=2023):
    chunks = []
    current_chunk = []
    current_length = 0
    for cond in conditions:
        if current_length + len(cond) + 4 > limit and current_chunk:
            chunks.append(" OR ".join(current_chunk))
            current_chunk = []
            current_length = 0
        current_chunk.append(cond)
        current_length += len(cond) + 4
    if current_chunk:
        chunks.append(" OR ".join(current_chunk))
    return chunks

if uploaded_file:
    content = uploaded_file.read().decode("utf-8")
    indicators = defaultdict(list)
    for line in content.strip().split('\n'):
        if not line or ',' not in line: continue
        parts = [x.strip().lower() for x in line.split(',', 1)]
        indicators[parts[1]].append(parts[0])

    domain_filter = ' WHERE "domainId"=\'3\' AND ' if client == "Tarshid" else ' WHERE '

    st.subheader(f"Generated Queries for {client}")

    for label, vals in indicators.items():
        # Get config, default to 'other' if not found
        conf = CONFIG.get(label, {'col': label, 'cat': label.upper(), 'is_ilike': False})
        
        with st.expander(f"{label.upper()} ({len(vals)} items)"):
            if conf['is_ilike']:
                conds = [f'"{conf["col"]}" ILIKE \'%{v}%\'' for v in vals]
                for i, chunk in enumerate(get_chunks(conds)):
                    st.code(f"SELECT 'IOC-HUNT-{conf['cat']}' AS 'Category', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"{conf['col']}\" AS '{conf['col']}' FROM events {domain_filter} ({chunk}) ORDER BY \"startTime\" DESC LAST 90 DAYS", language="sql")
            else:
                joined_vals = ",".join([f"'{v}'" for v in vals])
                st.code(f"SELECT 'IOC-HUNT-{conf['cat']}' AS 'Category', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"{conf['col']}\" AS '{conf['col']}' FROM events {domain_filter} (\"{conf['col']}\" IN ({joined_vals})) ORDER BY \"startTime\" DESC LAST 90 DAYS", language="sql")
