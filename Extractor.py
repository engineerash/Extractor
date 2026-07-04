import streamlit as st
from collections import defaultdict
import os

st.set_page_config(page_title="SOC IOC Generator", layout="wide")
st.title("🛡️ SOC Hunting: Multi-Client AQL Generator")

client = st.selectbox("Select Client", ["Tarshid", "Alraedah"])
uploaded_file = st.file_uploader("Upload your IOC file (value,label)", type=['csv', 'txt'])

file_basename = os.path.splitext(uploaded_file.name)[0] if uploaded_file else "UNKNOWN"

CONFIG = {
    'domain': {'col': 'URL HOST', 'cat': 'Domain', 'is_ilike': True, 'can_ref_set': False},
    'fqdn':   {'col': 'URL HOST', 'cat': 'Domain', 'is_ilike': True, 'can_ref_set': False},
    'url':    {'col': 'URL', 'cat': 'URL', 'is_ilike': True, 'can_ref_set': False},
    'mailsender': {'col': 'sender', 'cat': 'MailSender', 'is_ilike': True, 'can_ref_set': False},
    'subject':    {'col': 'subject', 'cat': 'MailSubject', 'is_ilike': True, 'can_ref_set': False},
    'md5':        {'col': 'MD5 Hash', 'cat': 'MD5', 'is_ilike': False, 'can_ref_set': True},
    'sha256':     {'col': 'SHA256 Hash', 'cat': 'SHA256', 'is_ilike': False, 'can_ref_set': True},
    'sha1':       {'col': 'SHA1 Hash', 'cat': 'SHA1', 'is_ilike': False, 'can_ref_set': True},
    'ip':         {'col': 'sourceIP', 'cat': 'IP', 'is_ilike': False, 'can_ref_set': True},
    'ip address': {'col': 'sourceIP', 'cat': 'IP', 'is_ilike': False, 'can_ref_set': True},
    'file':       {'col': 'Filename', 'cat': 'FileArtifacts', 'is_ilike': False, 'can_ref_set': False},
    'filename':   {'col': 'Filename', 'cat': 'FileArtifacts', 'is_ilike': False, 'can_ref_set': False}
}

def get_chunks(vals, conf, base_query, limit=2023):
    # Estimate the length of the IN clause or OR clause
    if conf['is_ilike']:
        full_cond = " OR ".join([f'"{conf["col"]}" ILIKE \'%{v}%\'' for v in vals])
    else:
        full_cond = f'("{conf["col"]}" IN ({",".join([f"\'{v}\'" for v in vals])}))'
    
    # If it fits, return as one chunk
    if len(base_query) + len(full_cond) <= limit:
        return [vals]
    
    # If it DOES NOT fit and can use ref set, return ref set trigger
    if conf['can_ref_set']:
        return "REF_SET"
        
    # If it doesn't fit and cannot use ref set, perform the manual split
    chunks = []
    current_chunk = []
    current_length = len(base_query)
    for v in vals:
        cond = f' OR "{conf["col"]}" ILIKE \'%{v}%\'' if conf['is_ilike'] else f"'{v}',"
        if current_length + len(cond) > limit and current_chunk:
            chunks.append(current_chunk)
            current_chunk = []
            current_length = len(base_query)
        current_chunk.append(v)
        current_length += len(cond)
    if current_chunk: chunks.append(current_chunk)
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
        base_query = f"SELECT '{scan_name}' AS 'Scan Name', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"{conf['col']}\" FROM events {domain_filter} "
        
        with st.expander(f"{label.upper()} ({len(vals)} items)"):
            result = get_chunks(vals, conf, base_query)
            
            if result == "REF_SET":
                st.info("Query too long. Using Reference Set instead.")
                st.code(f"{base_query} (\"{conf['col']}\" IN REFERENCE_SET('ThreatIntel_{conf['cat']}')) ORDER BY \"startTime\" DESC LAST 90 DAYS", language="sql")
            else:
                for i, chunk in enumerate(result):
                    if conf['is_ilike']:
                        cond = " OR ".join([f'"{conf["col"]}" ILIKE \'%{v}%\'' for v in chunk])
                        query = f"{base_query} ({cond}) ORDER BY \"startTime\" DESC LAST 90 DAYS"
                    else:
                        vals_str = ",".join([f"'{v}'" for v in chunk])
                        query = f"{base_query} (\"{conf['col']}\" IN ({vals_str})) ORDER BY \"startTime\" DESC LAST 90 DAYS"
                    if len(result) > 1: st.write(f"**Query Part {i+1}**")
                    st.code(query, language="sql")
