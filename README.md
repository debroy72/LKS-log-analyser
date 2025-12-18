# LKS Log Analyzer

Analyze large LANScale Communication Server (LKS) log files in a browser UI.  
The Streamlit app parses raw logs into structured records, applies filters, highlights key events, and even includes a local chatbot assistant (powered by Ollama) to answer natural‑language questions about the data set.

## Features
- Timestamp and PAW (LogS) filters so you can focus on the portion of the log that matters.
- Summary counters for PLU loads, message box traffic, FTP/TCP activity, exceptions, and other common events.
- Drill-down tables for MB messages, PLU loads, unhandled exceptions, generic errors, and uncategorized rows that do not fall into any bucket.
- Human readable decoding of PAW keypad codes (`[9] → 9 : CTRL_I Tab`, etc.) with console logging for unseen codes.
- Optional chatbot section that can search, summarize, or plot data using a local LLM via Ollama.

## Requirements
- Python ≥ 3.10 (3.13 recommended, matching the included `lks_env` virtual environment).
- pip for installing dependencies.
- (Optional) [Ollama](https://ollama.ai/) with a llama3 model pulled locally if you want the chatbot responses.

Python dependencies:
```
streamlit
pandas
matplotlib
ollama
```

## Quick Start
```bash
git clone https://github.com/debroy72/LKS-log-analyser.git
cd LKS-log-analyser

# Create a virtual environment (optional but recommended)
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install the app requirements
pip install -r requirements.txt  # if provided
# or install manually:
pip install streamlit pandas matplotlib ollama

# Launch the Streamlit UI
streamlit run lks_log_analyzer_app.py
```

The repository already contains a virtual environment named `lks_env`; you can reuse it locally with:
```bash
./lks_env/bin/streamlit run lks_log_analyzer_app.py
```

## Using the App
1. Open the URL that Streamlit prints (default `http://localhost:8501`).
2. Upload an `.log` or `.txt` file from the LKS system.
3. (Optional) Apply the timestamp or PAW-only filters.
4. Review the **Summary** table to see counts, then explore the drill-down tabs:
   - `MB Messages`, `PLU Loads`, `Unhandled Exceptions`, `Other Errors`, or `Uncategorized Logs`.
5. Scroll down to inspect error details or download CSV excerpts.
6. Enable the chatbot section, choose an Ollama model (requires a running Ollama daemon), and ask natural language questions about the parsed log.

## Troubleshooting
- **Missing dependencies**: ensure your virtual environment is activated before installing or running Streamlit.
- **`ollama` errors**: the chatbot is optional; disable the checkbox if Ollama is not available.
- **Unknown key codes**: the parser logs unseen PAW key codes to the terminal so you can extend the lookup table easily.

## License
MIT (or update to your preferred license).
