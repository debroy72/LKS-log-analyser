import streamlit as st

from parsing_utils import parse_lines
from ui_components import (
    render_timestamp_filter,
    render_paw_filter,
    render_summary,
    render_drilldowns,
    render_error_details,
    render_full_log,
)
from chatbot_section import render_chatbot


def main():
    st.set_page_config(page_title="LKS Log Analyzer", layout="wide")
    st.title("LKS Log Analyzer")
    st.caption("Parse LANScale Communication Server (LKS) logs, summarize key metrics, and inspect errors.")

    uploaded = st.file_uploader("Upload an LKS log file (.log or .txt)", type=["log", "txt"])
    if uploaded is None:
        st.info("Upload a log file to begin.")
        render_chatbot(df=None)
        return

    content = uploaded.read().decode("utf-8", errors="ignore").splitlines()
    df = parse_lines(content)

    if df.empty:
        st.warning("No records parsed from the file.")
        return

    filtered_df = render_timestamp_filter(df)
    filtered_df = render_paw_filter(filtered_df)

    render_summary(filtered_df)
    render_drilldowns(filtered_df)
    render_error_details(filtered_df)
    render_full_log(filtered_df)
    render_chatbot(filtered_df)


if __name__ == "__main__":
    main()
