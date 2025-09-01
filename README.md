# APK Analyzer Project

This project is a Flask-based APK Analyzer web application that allows users to upload and analyze APK files for malicious or fake behavior. It integrates heuristics and a small ML model for detection.

## Folder Structure

```
apk_analyzer_project/
│── app.py                # Flask backend
│── analyzer.py           # APK analysis logic
│── model.py              # ML model training/loading
│── index.html            # Frontend UI (single-page)
│── requirements.txt      # Python dependencies
│── Dockerfile            # Docker build file
│── docker-compose.yml    # Compose setup
│── README.md             # Project documentation
│── uploads/              # Uploaded APKs (mounted volume)
```

## Run Locally

```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000` in your browser.

## Run with Docker

```bash
docker-compose up --build
```

This will start the Flask app on `http://localhost:5000` and mount `uploads/` for persistent storage.
