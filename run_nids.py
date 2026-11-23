"""Run from the AI-NIDS repository root: python run_nids.py"""
from dashboard.fast_app import create_app

app = create_app()

if __name__ == "__main__":
    print("AI-NIDS dashboard: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
