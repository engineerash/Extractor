import streamlit as st
from collections import defaultdict

st.set_page_config(page_title="Multi-Client IOC Generator", layout="wide")
st.title("🛡️ SOC Hunting: Multi-Client AQL Generator")

client = st.selectbox("Select Client", ["Tarshid", "Alraedah"])
uploaded_file = st.file_uploader("Upload your IOC file (Format: value,label)", type=['csv', 'txt'])

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
        val, label = [x.strip() for x in line.split(',', 1)]
        indicators[label.lower()].append(val)

    domain_filter = ' WHERE "domainId"=\'3\' AND ' if client == "Tarshid" else ' WHERE '

    st.subheader(f"Generated Queries for {client}")

    for label, vals in indicators.items():
        count = len(vals)
        # Use an expander for EVERY type to maintain consistent style
        with st.expander(f"### {label.upper()} ({count} items)"):
            
            # ILIKE Types
            if label in ['url', 'domain', 'mailsender', 'subject']:
                col_map = {"url": "URL", "domain": "URL HOST", "mailsender": "sender", "subject": "subject"}
                cat_map = {"url": "URL", "domain": "Domain", "mailsender": "MailSender", "subject": "MailSubject"}
                col_name = col_map[label]
                
                conds = [f'"{col_name}" ILIKE \'%{v}%\'' for v in vals]
                chunks = get_chunks(conds)
                for i, chunk in enumerate(chunks):
                    query = f"SELECT 'IOC-HUNT-{cat_map[label]}' AS 'Category', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"{col_name}\" AS '{col_name}' FROM events {domain_filter} ({chunk}) ORDER BY \"startTime\" DESC LAST 90 DAYS"
                    st.write(f"**Query Part {i+1}**")
                    st.code(query, language="sql")
            
            # IN Types
            elif label in ['md5', 'sha256', 'ip', 'fileartifacts']:
                if label == 'fileartifacts':
                    query = f"SELECT 'IOC-HUNT-FileArtifacts' AS 'Category', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"Filename\" AS 'File Name', \"File Directory\" AS 'File Directory' FROM events {domain_filter} (\"Filename\" IN ({','.join([f"'{v}'" for v in vals])})) ORDER BY \"startTime\" DESC LAST 90 DAYS"
                    st.code(query, language="sql")
                else:
                    col_name = {"md5": "MD5 Hash", "sha256": "SHA256 Hash", "ip": "sourceIP"}[label]
                    joined_vals = ",".join([f"'{v}'" for v in vals])
                    query = f"SELECT 'IOC-HUNT-{label.upper()}' AS 'Category', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"{col_name}\" AS '{label.upper()}' FROM events {domain_filter} (\"{col_name}\" IN ({joined_vals})) ORDER BY \"startTime\" DESC LAST 90 DAYS"
                    st.code(query, language="sql")
