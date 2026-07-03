import streamlit as st

st.set_page_config(page_title="IOC to AQL Generator", layout="wide")
st.title("🛡️ SOC Hunting: Individual AQL Generator")

uploaded_file = st.file_uploader("Upload your IOC file (CSV/TXT)", type=['csv', 'txt'])

if uploaded_file:
    # Use string decoding for the file
    content = uploaded_file.read().decode("utf-8")
    
    # Process indicators into a list
    indicators = []
    for line in content.strip().split('\n'):
        if not line or ',' not in line: continue
        val, label = [x.strip().lower() for x in line.split(',', 1)]
        indicators.append({"value": val, "type": label})

    # Define Query Templates
    templates = {
        'domain': 'SELECT QIDNAME(qid) AS "Event Name", "URL HOST" AS "Host" FROM events WHERE "domainId"=\'3\' AND "URL HOST" ILIKE \'%{val}%\' LAST 90 DAYS',
        'ip': 'SELECT QIDNAME(qid) AS "Event Name", "Source IP", "Destination IP" FROM events WHERE "domainId"=\'3\' AND ("Source IP" = \'{val}\' OR "Destination IP" = \'{val}\') LAST 90 DAYS',
        'url': 'SELECT QIDNAME(qid) AS "Event Name", "URL" FROM events WHERE "domainId"=\'3\' AND "URL" ILIKE \'%{val}%\' LAST 90 DAYS',
        'md5': 'SELECT QIDNAME(qid) AS "Event Name", "MD5 Hash" FROM events WHERE "domainId"=\'3\' AND "MD5 Hash" = \'{val}\' LAST 90 DAYS',
        'sha1': 'SELECT QIDNAME(qid) AS "Event Name", "SHA1 Hash" FROM events WHERE "domainId"=\'3\' AND "SHA1 Hash" = \'{val}\' LAST 90 DAYS',
        'sha256': 'SELECT QIDNAME(qid) AS "Event Name", "SHA256 Hash" FROM events WHERE "domainId"=\'3\' AND "SHA256 Hash" = \'{val}\' LAST 90 DAYS',
        'filename': 'SELECT QIDNAME(qid) AS "Event Name", "File Name" FROM events WHERE "domainId"=\'3\' AND "File Name" ILIKE \'%{val}%\' LAST 90 DAYS'
    }

    # Helper to map various input labels to our template keys
    def get_template_key(label):
        mapping = {
            'fqdn': 'domain', 'domain': 'domain',
            'ip': 'ip', 'ip address': 'ip',
            'url': 'url',
            'md5': 'md5', 'sha1': 'sha1', 'sha256': 'sha256',
            'filename': 'filename', 'file': 'filename'
        }
        return mapping.get(label)

    st.subheader("Generated Queries")
    
    # Iterate and display
    for item in indicators:
        key = get_template_key(item['type'])
        if key and key in templates:
            with st.expander(f"[{item['type'].upper()}] {item['value']}"):
                st.code(templates[key].format(val=item['value']), language="sql")
        else:
            st.warning(f"Unsupported or unknown indicator type: {item['type']} ({item['value']})")
