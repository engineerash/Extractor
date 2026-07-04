import streamlit as st
import pandas as pd
from ioc_fanger import fang

def process_iocs(df):
    """Cleans and deduplicates IOCs from a DataFrame."""
    # Assuming 'Indicator' is the column containing the fanged data
    raw_iocs = df['Indicator'].dropna().tolist()
    
    # "Fang" the IOCs and use a set for automatic deduplication
    cleaned_iocs = {fang(ioc) for ioc in raw_iocs}
    
    return sorted(list(cleaned_iocs))

st.title("IOC Fanger & AQL Formatter")

uploaded_file = st.file_uploader("Upload your fanged IOC Excel/CSV", type=["xlsx", "csv"])

if uploaded_file:
    df = pd.read_excel(uploaded_file) if uploaded_file.name.endswith('.xlsx') else pd.read_csv(uploaded_file)
    
    if st.button("Process IOCs"):
        results = process_iocs(df)
        st.write("### Cleaned IOCs:")
        st.code("\n".join(results))
        
        # Prepare for download
        results_str = "\n".join(results)
        st.download_button(
            label="Download Cleaned IOCs",
            data=results_str,
            file_name="cleaned_iocs.txt",
            mime="text/plain"
        )
