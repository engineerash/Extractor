import streamlit as st
from collections import defaultdict

st.set_page_config(page_title="IOC to AQL Generator", layout="wide")
st.title("🛡️ SOC Hunting: Type-Based AQL Generator")

uploaded_file = st.file_uploader("Upload your IOC file (CSV/TXT)", type=['csv', 'txt'])

if uploaded_file:
    content = uploaded_file.read().decode("utf-8")
    
    # 1. Group indicators by type
    grouped_indicators = defaultdict(list)
    for line in content.strip().split('\n'):
        if not line or ',' not in line: continue
        val, label = [x.strip().lower() for x in line.split(',', 1)]
        
        # Normalize labels
        mapping = {
            'fqdn': 'domain', 'domain': 'domain',
            'ip': 'ip', 'ip address': 'ip',
            'url': 'url',
            'md5': 'md5', 'sha1': 'sha1', 'sha256': 'sha256',
            'filename': 'filename', 'file': 'filename'
        }
        category = mapping.get(label, 'other')
        if category != 'other':
            grouped_indicators[category].append(val)

    # 2. Define Query Templates for grouped data
    # We use " OR " to join multiple values for the same type
    templates = {
        'domain': 'SELECT QIDNAME(qid) AS "Event Name", "URL HOST" FROM events WHERE "domainId"=\'3\' AND ({query}) LAST 90 DAYS',
        'ip': 'SELECT QIDNAME(qid) AS "Event Name", "Source IP", "Destination IP" FROM events WHERE "domainId"=\'3\' AND ({query}) LAST 90 DAYS',
        'url': 'SELECT QIDNAME(qid) AS "Event Name", "URL" FROM events WHERE "domainId"=\'3\' AND ({query}) LAST 90 DAYS',
        'md5': 'SELECT QIDNAME(qid) AS "Event Name", "MD5 Hash" FROM events WHERE "domainId"=\'3\' AND ({query}) LAST 90 DAYS',
        'sha1': 'SELECT QIDNAME(qid) AS "Event Name", "SHA1 Hash" FROM events WHERE "domainId"=\'3\' AND ({query}) LAST 90 DAYS',
        'sha256': 'SELECT QIDNAME(qid) AS "Event Name", "SHA256 Hash" FROM events WHERE "domainId"=\'3\' AND ({query}) LAST 90 DAYS',
        'filename': 'SELECT QIDNAME(qid) AS "Event Name", "File Name" FROM events WHERE "domainId"=\'3\' AND ({query}) LAST 90 DAYS'
    }

    st.subheader("Generated Grouped Queries")
    
    # 3. Generate one query per category
    for category, values in grouped_indicators.items():
        if category in templates:
            # Create the OR condition string
            if category == 'domain':
                conds = [f'"URL HOST" ILIKE \'%{v}%\'' for v in values]
            elif category == 'ip':
                conds = [f'"Source IP" = \'{v}\' OR "Destination IP" = \'{v}\'' for v in values]
            elif category == 'url':
                conds = [f'"URL" ILIKE \'%{v}%\'' for v in values]
            elif category == 'filename':
                conds = [f'"File Name" ILIKE \'%{v}%\'' for v in values]
            else: # Hashes
                hash_col = {"md5": "MD5 Hash", "sha1": "SHA1 Hash", "sha256": "SHA256 Hash"}[category]
                formatted_list = ",".join([f"'{v}'" for v in values])
                conds = [f'"{hash_col}" IN ({formatted_list})']
            
            # Combine conditions and display
            full_query = templates[category].format(query=" OR ".join(conds))
            with st.expander(f"Search for all {category.upper()}s ({len(values)} items)"):
                st.code(full_query, language="sql")
