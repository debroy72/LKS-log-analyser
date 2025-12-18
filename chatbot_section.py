import re
from typing import Optional

import matplotlib.pyplot as plt
import ollama
import pandas as pd
import streamlit as st

from parsing_utils import TAG_MAP, COMPILED_TS, extract_timestamp

CHATBOT_STOPWORDS = {
    "show",
    "list",
    "please",
    "about",
    "details",
    "detail",
    "give",
    "display",
    "need",
    "want",
    "tell",
    "rows",
    "row",
    "lines",
    "line",
    "entries",
    "entry",
    "data",
    "info",
    "information",
    "using",
    "use",
    "llama",
}


def ollama_status(model_name: str = "llama3"):
    try:
        listed = ollama.list() or {}
        models = listed.get("models", [])
        model_present = any(
            (m.get("name") or m.get("model") or "").startswith(model_name)
            for m in models
        )
        return True, model_present
    except Exception:
        return False, False


def render_chatbot(df: pd.DataFrame | None):
    st.subheader("🤖 LKS Log Chatbot Assistant (Offline)")
    st.caption("Ask in plain English — I can explain logs or even plot trends for you. (Runs 100% locally using Ollama)")

    if df is None or df.empty:
        st.info("Upload and parse a log file first to enable the chatbot.")
        return

    use_llm = st.checkbox(
        "Use local LLM for free-form answers (slower)",
        value=False,
        help="Keeps things snappy when off. Turn on to let Ollama generate full answers.",
    )
    selected_model = st.selectbox(
        "LLM model (lighter = faster)",
        options=["llama3:8b", "llama3", "llama3:70b"],
        index=0,
        help="Use llama3:8b for speed; larger models give richer answers but are slower.",
    )
    col_rows, col_ctx = st.columns(2)
    with col_rows:
        chat_row_limit = int(
            st.number_input(
                "Rows per chatbot answer",
                min_value=1,
                max_value=500,
                value=10,
                step=1,
                help="Controls how many rows each chatbot query returns.",
            )
        )
    with col_ctx:
        chat_context_window = int(
            st.number_input(
                "Context window (± rows)",
                min_value=0,
                max_value=100,
                value=10,
                step=1,
                help="How many surrounding rows to include when showing context.",
            )
        )

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    user_query = st.chat_input("Ask a question about the log...")

    if not user_query:
        return

    st.session_state.chat_history.append({"role": "user", "content": user_query})
    with st.chat_message("user"):
        st.markdown(user_query)

    q = user_query.lower()
    query_result = None
    generated_plot = None
    context_snippets = None
    ollama_ready, model_ready = ollama_status(selected_model)

    def capture_context_from_pos(pos):
        if pos is None or chat_context_window < 0:
            return None
        start = max(0, pos - chat_context_window)
        end = pos + chat_context_window + 1
        return df.iloc[start:end][["line_no", "timestamp", "tag", "message", "raw"]]

    line_hint = None
    ts_hint = None
    line_match = re.search(r"(?i)\b(?:line|row)\s*(\d+)\b", user_query)
    if not line_match:
        line_match = re.search(r"\b(\d{3,})\b", user_query)
    if line_match:
        try:
            line_hint = int(line_match.group(1))
        except ValueError:
            line_hint = None
    for cre in COMPILED_TS:
        tm = cre.search(user_query)
        if tm:
            ts_hint = extract_timestamp(tm.group(0))
            break
    row_count_hint: Optional[int] = None
    row_direction = "first"
    row_count_match = re.search(r"(?i)\b(last|first)?\s*(\d+)\s+rows?\b", user_query)
    if row_count_match:
        dir_token = (row_count_match.group(1) or "").lower()
        try:
            row_count_hint = int(row_count_match.group(2))
            if row_count_hint <= 0:
                row_count_hint = None
        except ValueError:
            row_count_hint = None
        if dir_token == "last":
            row_direction = "last"

    raw_terms = re.findall(r"[A-Za-z0-9_+#:-]+", user_query)
    search_terms = [
        w.lower()
        for w in raw_terms
        if len(w) > 2 and not w.isdigit() and w.lower() not in CHATBOT_STOPWORDS
    ]

    if ("unhandled" in q) or ("** ue" in q) or (" ue" in q):
        ue_df = df[df["tag"] == "** UE"].copy()
        query_result = ue_df[["line_no", "timestamp", "message", "raw"]].tail(chat_row_limit)
        if not ue_df.empty:
            target_idx = None
            if "first" in q:
                target_idx = ue_df.index[0]
            elif "last" in q or "latest" in q:
                target_idx = ue_df.index[-1]
            elif line_hint is not None:
                nearest = (ue_df["line_no"] - line_hint).abs().idxmin()
                target_idx = nearest
            elif ts_hint:
                try:
                    ts_dt = pd.to_datetime(ts_hint)
                    nearest = (ue_df["timestamp_dt"] - ts_dt).abs().idxmin()
                    target_idx = nearest
                except Exception:
                    target_idx = None
            if target_idx is None:
                target_idx = ue_df.index[-1]

            try:
                pos = df.index.get_loc(target_idx)
            except KeyError:
                pos = None
            if pos is not None:
                context_snippets = capture_context_from_pos(pos)

    if query_result is None and line_hint is not None:
        try:
            nearest_idx = (df["line_no"] - line_hint).abs().idxmin()
            query_result = df.loc[[nearest_idx], ["line_no", "timestamp", "tag", "description", "message", "raw"]]
            pos = df.index.get_loc(nearest_idx)
            context_snippets = capture_context_from_pos(pos)
        except Exception:
            query_result = None

    elif "mb" in q and ("show" in q or "list" in q):
        mb_df = df[df["tag"] == "MB"][["timestamp", "message"]].copy()
        query_result = mb_df.tail(chat_row_limit)

    elif "plu" in q:
        plu_df = df[df["tag"] == "LOAD_PLU"][["timestamp", "message"]].copy()
        query_result = plu_df.tail(chat_row_limit)

    elif "error" in q or "exception" in q:
        err_mask = (
            df["tag"].isin(["** UE", "**"])
            | df["raw"].str.contains("Exception", na=False)
            | df["raw"].str.contains("Error", na=False, case=False)
        )
        query_result = df[err_mask][["timestamp", "tag", "message"]].tail(chat_row_limit)

    elif "tcp" in q or "connection" in q:
        query_result = df[df["raw"].str.contains("Connection established", na=False)][["timestamp", "message"]].tail(chat_row_limit)

    if query_result is None and row_count_hint:
        max_rows = min(row_count_hint, 500)
        base_cols = ["line_no", "timestamp", "tag", "description", "message", "raw"]
        subset = df.loc[:, base_cols]
        if row_direction == "last":
            query_result = subset.tail(max_rows)
        else:
            query_result = subset.head(max_rows)

    if query_result is None and search_terms:
        mask = pd.Series(False, index=df.index)
        for term in search_terms:
            mask = mask | (
                df["raw"].str.contains(term, case=False, na=False)
                | df["message"].str.contains(term, case=False, na=False)
                | df["description"].str.contains(term, case=False, na=False)
                | df["tag"].str.contains(term, case=False, na=False)
            )
        hits = df.loc[mask, ["line_no", "timestamp", "tag", "description", "message", "raw"]]
        if not hits.empty:
            query_result = hits.head(chat_row_limit)
            first_idx = hits.index[0]
            try:
                pos = df.index.get_loc(first_idx)
            except KeyError:
                pos = None
            if pos is not None:
                context_snippets = capture_context_from_pos(pos)

    if any(k in q for k in ["plot", "graph", "trend", "chart", "visualize", "count over time"]):
        try:
            if "mb" in q:
                temp = df[df["tag"] == "MB"].copy()
                temp["hour"] = temp["timestamp_dt"].dt.floor("H")
                plot_data = temp.groupby("hour").size()
                plt.figure(figsize=(8, 3))
                plt.plot(plot_data.index, plot_data.values, marker="o")
                plt.title("MB Message Frequency Over Time")
                plt.xlabel("Time (hour)")
                plt.ylabel("Count")
                plt.xticks(rotation=45)
                plt.tight_layout()
                st.pyplot(plt)
                generated_plot = "MB message frequency plot"
            elif "error" in q or "exception" in q:
                temp = df[
                    df["raw"].str.contains("Exception|Error", case=False, na=False)
                ].copy()
                temp["hour"] = temp["timestamp_dt"].dt.floor("H")
                plot_data = temp.groupby("hour").size()
                plt.figure(figsize=(8, 3))
                plt.bar(plot_data.index, plot_data.values)
                plt.title("Error / Exception Frequency Over Time")
                plt.xlabel("Time (hour)")
                plt.ylabel("Count")
                plt.xticks(rotation=45)
                plt.tight_layout()
                st.pyplot(plt)
                generated_plot = "Error frequency plot"
            elif "plu" in q:
                temp = df[df["tag"] == "LOAD_PLU"].copy()
                temp["hour"] = temp["timestamp_dt"].dt.floor("H")
                plot_data = temp.groupby("hour").size()
                plt.figure(figsize=(8, 3))
                plt.bar(plot_data.index, plot_data.values, color="teal")
                plt.title("PLU Loads Over Time")
                plt.xlabel("Time (hour)")
                plt.ylabel("Count")
                plt.xticks(rotation=45)
                plt.tight_layout()
                st.pyplot(plt)
                generated_plot = "PLU load trend plot"
        except Exception as e:
            st.error(f"Error while plotting: {e}")

    if query_result is not None and not query_result.empty:
        with st.chat_message("assistant"):
            st.markdown("Here’s what I found:")
            st.dataframe(query_result, use_container_width=True)
            st.markdown(f"**{len(query_result)} matching entries shown.**")
            try:
                ts_col = pd.to_datetime(query_result["timestamp"], errors="coerce")
                span_start = ts_col.min()
                span_end = ts_col.max()
                top_tags = (
                    query_result["tag"]
                    .value_counts(dropna=True)
                    .head(5)
                    .to_dict()
                    if "tag" in query_result.columns
                    else {}
                )
                tag_bits = "; ".join([f"{k or 'None'}: {v}" for k, v in top_tags.items()])
                summary_lines = []
                if pd.notna(span_start) and pd.notna(span_end):
                    summary_lines.append(f"Window: {span_start} → {span_end}")
                summary_lines.append(f"Total rows: {len(query_result)}")
                if tag_bits:
                    summary_lines.append(f"Top tags: {tag_bits}")
                st.markdown("💡 Summary: " + " | ".join(summary_lines))
            except Exception:
                pass
            if context_snippets is not None and not context_snippets.empty:
                if chat_context_window:
                    ctx_label = f"Context around selection (±{chat_context_window} rows):"
                else:
                    ctx_label = "Context around selection (selected row only):"
                st.markdown(ctx_label)
                st.dataframe(context_snippets, use_container_width=True, hide_index=True)
            st.session_state.chat_history.append(
                {"role": "assistant", "content": f"Displayed {len(query_result)} entries for '{user_query}'."}
            )
    elif not generated_plot and not use_llm:
        with st.chat_message("assistant"):
            msg = "Local LLM is off. Toggle the switch above if you want a full answer (may take longer)."
            st.info(msg)
            st.session_state.chat_history.append({"role": "assistant", "content": msg})
    elif not generated_plot:
        tag_reference = "\n".join([f"{k} → {v}" for k, v in TAG_MAP.items()])
        context_text = "\n".join(
            df.tail(50)[["timestamp", "tag", "message"]]
            .astype(str)
            .apply(lambda r: f"[{r.timestamp}] {r.tag}: {r.message}", axis=1)
            .tolist()
        )

        prompt = f"""
You are an expert in interpreting LANScale Communication Server logs.
Understand these tags:
{tag_reference}

Here are recent log lines:
{context_text}

User question: {user_query}
Answer clearly and concisely based on context.
"""

        with st.chat_message("assistant"):
            if not ollama_ready:
                msg = "⚠️ Local model unavailable. Start the Ollama app/daemon."
                st.warning(msg)
                st.session_state.chat_history.append({"role": "assistant", "content": msg})
            elif not model_ready:
                msg = f"⚠️ Model `{selected_model}` missing. Run `ollama pull {selected_model}` (or pick a model you have) and retry."
                st.warning(msg)
                st.session_state.chat_history.append({"role": "assistant", "content": msg})
            else:
                st.markdown("💭 Thinking (local model)...")
                try:
                    response = ollama.chat(
                        model=selected_model,
                        messages=[{"role": "user", "content": prompt}],
                        stream=False,
                    )
                    answer = response["message"]["content"]
                except Exception as e:
                    err = str(e)
                    if "404" in err or "not found" in err.lower():
                        answer = "⚠️ Model `llama3` not available. Run `ollama pull llama3` (or `llama3:8b`) and retry."
                    else:
                        answer = f"⚠️ Local model error: {err}"

                st.markdown(answer)
                st.session_state.chat_history.append({"role": "assistant", "content": answer})
