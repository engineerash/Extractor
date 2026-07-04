import streamlit as st
from collections import defaultdict
import os

st.set_page_config(page_title="SOC IOC Generator", layout="wide")
st.title("🛡️ SOC Hunting: Multi-Client AQL Generator")

client = st.selectbox("Select Client", ["Tarshid", "Alraedah"])
uploaded_file = st.file_uploader("Upload your IOC file (value,label)", type=['csv', 'txt'])

file_basename = os.path.splitext(uploaded_file.name)[0] if uploaded_file else "UNKNOWN"

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
    'filename':   {'col': 'Filename', 'cat': 'FileArtifacts', 'is_ilike': False},
    'fileartifacts': {'col': 'Filename', 'cat': 'FileArtifacts', 'is_ilike': False}
}

# Improved chunking to handle both ILIKE (OR) and IN lists
def get_chunks(items, is_ilike, col, limit=2023):
    chunks = []
    current_chunk = []
    current_length = 0
    
    # Base query template length (approximate)
    base_len = 200 
    
    for item in items:
        # Calculate length of the condition
        cond = f'"{col}" ILIKE \'%{item}%\'' if is_ilike else f"'{item}'"
        
        if current_length + len(cond) + 4 > (limit - base_len) and current_chunk:
            chunks.append(current_chunk)
            current_chunk = []
            current_length = 0
        current_chunk.append(item)
        current_length += len(cond) + 4
        
    if current_chunk:
        chunks.append(current_chunk)
    return chunks

if uploaded_file:
    content = uploaded_file.read().decode("utf-8")
    indicators = defaultdict(list)
    for line in content.strip().split('\n'):
        if not line or ',' not in line: continue
        parts = [x.strip().lower() for x in line.rsplit(',', 1)]
        if len(parts) == 2 and parts[1] in CONFIG:
            indicators[parts[1]].append(parts[0])

    domain_filter = ' WHERE "domainId"=\'3\' AND ' if client == "Tarshid" else ' WHERE '
    st.subheader(f"Generated Queries for {client}")

    for label, vals in indicators.items():
        conf = CONFIG[label]
        scan_name = f"{file_basename}-HUNT-{conf['cat']}"
        
        with st.expander(f"{label.upper()} ({len(vals)} items)"):
            chunks = get_chunks(vals, conf['is_ilike'], conf['col'])
            
            for i, chunk in enumerate(chunks):
                if conf['is_ilike']:
                    condition = " OR ".join([f'"{conf["col"]}" ILIKE \'%{v}%\'' for v in chunk])
                    query = f"SELECT '{scan_name}' AS 'Scan Name', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"{conf['col']}\" FROM events {domain_filter} ({condition}) ORDER BY \"startTime\" DESC LAST 90 DAYS"
                else:
                    joined_vals = ",".join([f"'{v}'" for v in chunk])
                    query = f"SELECT '{scan_name}' AS 'Scan Name', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"{conf['col']}\" FROM events {domain_filter} (\"{conf['col']}\" IN ({joined_vals})) ORDER BY \"startTime\" DESC LAST 90 DAYS"
                
                st.write(f"**Query Part {i+1}**")
                st.code(query, language="sql")
