import streamlit as st
from collections import defaultdict

st.set_page_config(page_title="Multi-Client Mail IOC Generator", layout="wide")
st.title("🛡️ SOC Hunting: Mail-Only AQL Generator")

client = st.selectbox("Select Client", ["Tarshid", "Alraedah"])
uploaded_file = st.file_uploader("Upload your IOC file", type=['csv', 'txt'])

# --- CONFIGURE ONLY MAIL-RELATED TYPES ---
# Add or remove types here to control what is processed
VALID_MAIL_TYPES = ['mailsender', 'subject', 'url', 'domain']

CONFIG = {
    'domain': {'col': 'URL HOST', 'cat': 'Domain', 'is_ilike': True},
    'fqdn':   {'col': 'URL HOST', 'cat': 'Domain', 'is_ilike': True},
    'url':    {'col': 'URL', 'cat': 'URL', 'is_ilike': True},
    'mailsender': {'col': 'sender', 'cat': 'MailSender', 'is_ilike': True},
    'subject':    {'col': 'subject', 'cat': 'MailSubject', 'is_ilike': True}
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
        parts = [x.strip().lower() for x in line.rsplit(',', 1)]
        
        # --- IGNORE FILTER ---
        # Only add to indicators if the label is in our VALID_MAIL_TYPES list
        if len(parts) == 2 and parts[1] in VALID_MAIL_TYPES:
            indicators[parts[1]].append(parts[0])

    domain_filter = ' WHERE "domainId"=\'3\' AND ' if client == "Tarshid" else ' WHERE '

    st.subheader(f"Generated Mail Queries for {client}")

    if not indicators:
        st.info("No valid mail-related IOCs found in the file.")
    
    for label, vals in indicators.items():
        conf = CONFIG.get(label)
        
        with st.expander(f"{label.upper()} ({len(vals)} items)"):
            if conf['is_ilike']:
                conds = [f'"{conf["col"]}" ILIKE \'%{v}%\'' for v in vals]
                for i, chunk in enumerate(get_chunks(conds)):
                    st.write(f"**Query Part {i+1}**")
                    st.code(f"SELECT 'IOC-HUNT-{conf['cat']}' AS 'Category', QIDNAME(qid) AS 'Event Name', logsourcename(logSourceId) AS 'Log Source', DATEFORMAT(\"startTime\",'yyyy-MM-dd HH:mm:ss') AS 'Time', \"{conf['col']}\" AS '{conf['col']}' FROM events {domain_filter} ({chunk}) ORDER BY \"startTime\" DESC LAST 90 DAYS", language="sql")
