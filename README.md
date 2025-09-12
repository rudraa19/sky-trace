# 🔒 Sky Trace – AI-Powered Security Anomaly Detection

**Sky Trace** is an advanced **AI/ML-based anomaly detection system** for monitoring login activity, detecting anomalies, and generating security insights.  
It combines **real-time dashboards, geolocation analysis, anomaly detection models, and automated reporting** into a modular workflow.

---

## 🔒 Key Features
- 📂 **Data Upload & Preprocessing** – CSV validation, cleaning, and feature extraction  
- 🤖 **AI/ML Detection** – Isolation Forest, DBSCAN, and statistical anomaly detection  
- 🌍 **Geolocation Analysis** – IP-to-location mapping, impossible travel detection, VPN/proxy checks  
- 📊 **Real-time Dashboard** – Interactive monitoring with Plotly/Altair charts & Folium maps  
- ⚠️ **Risk Scoring** – Configurable 0–1 scale with criticality levels (Low/Medium/High/Critical)  
- 📋 **Automated Reports** – Executive, technical, and incident reports (export to CSV/PDF)  
- 🔄 **Notifications** – Optional email alerts with SendGrid integration  
- ☁️ **Flexible Deployment** – Works locally, on Replit, or cloud platforms (Heroku, AWS, Streamlit Cloud)  

---

## 🏗️ Architecture

```

┌───────────────┐   ┌───────────────────┐   ┌───────────────┐
│   Data Upload │ → │ Anomaly Detection │ → │   Dashboard   │
│   - CSV Input │   │ - ML Algorithms   │   │ - Monitoring  │
│   - Processing│   │ - Geolocation     │   │ - Alerts      │
└───────────────┘   └───────────────────┘   └───────────────┘
                            │
                            v
                    ┌──────────────────┐
                    │ Security Reports │
                    │ - Executive      │
                    │ - Technical      │
                    │ - Incident       │
                    └──────────────────┘

```

---

## 📂 Project Structure
```

sky-trace/
│
├── app.py                      # Main entry point
├── pyproject.toml              # Project dependencies and metadata
├── requirements.txt            # Alternative dependency list
├── pages/                      # Multi-page Streamlit app
│   ├── 1_Data_Upload.py
│   ├── 2_Anomaly_Detection.py
│   ├── 3_Real_time_Dashboard.py
│   └── 4_Security_Reports.py
│
├── utils/                      # Utility modules
│   ├── data_processor.py      # Data validation & preprocessing
│   ├── ml_detector.py         # ML anomaly detection models
│   ├── geolocation.py          # IP geolocation & travel analysis
│   ├── visualizations.py       # Plotly/Altair/Folium charts
│   └── report_generator.py    # Automated reporting
│
└── .streamlit/config.toml      # Streamlit server configuration

````

---

## ⚙️ Setup & Installation

### Prerequisites
- Python **3.11+**
- [Streamlit](https://streamlit.io/) for the dashboard  
- (Optional) SendGrid API key for email alerts  

### Installation
```bash
# Clone the repository
git clone https://github.com/rudraa19/sky-trace.git
cd sky-trace

# Create and activate a virtual environment
python3 -m venv myenv
source myenv/bin/activate    # Linux/Mac
myenv\Scripts\activate       # Windows

# Install dependencies
pip install -r requirements.txt
````

### Run Application

```bash
streamlit run app.py
```

Access the app at **[http://localhost:8501](http://localhost:8501)** (or configured port).

---

## 📖 Usage Guide

### Step 1: Data Upload

Upload CSV login data:

```csv
timestamp,user_id,ip_address,user_agent
2024-01-15 09:30:45,user001,192.168.1.100,Mozilla/5.0
```

### Step 2: Anomaly Detection

* Choose algorithm (Isolation Forest / DBSCAN / Statistical Rules)
* Configure:

  * Contamination rate
  * Risk threshold (default **0.7**)
  * Enable/disable geolocation analysis

### Step 3: Real-time Dashboard

* Monitor:

  * Total logins & anomalies
  * Risk distribution & user profiles
  * Geographic login patterns

### Step 4: Security Reports

* Generate:

  * 📊 Executive summary
  * 🛠 Technical analysis
  * 🚨 Incident-specific reports
* Export as **CSV** or **PDF**

---

## 🔧 Configuration

### Risk Levels

* Low: **0.0 – 0.4**
* Medium: **0.4 – 0.6**
* High: **0.6 – 0.8**
* Critical: **0.8 – 1.0**

### Algorithm Weights (default)

* Isolation Forest: **40%**
* DBSCAN: **30%**
* Statistical Rules: **30%**

### Geolocation Settings

* API: `ip-api.com` (1000 requests/hour)
* Impossible Travel: >1000 km/h

---

## ☁️ Deployment Options

### Local / Replit

```bash
streamlit run app.py --server.port 5000
```

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["streamlit", "run", "app.py", "--server.port", "5000", "--server.address", "0.0.0.0"]
```

### Cloud

* **Streamlit Cloud** – GitHub integration (auto-deploy)
* **Heroku** – Use `Procfile` with `web: streamlit run app.py --server.port $PORT`
* **AWS/GCP/Azure** – Containerized deployment

---

## 👥 Contributors

* [rudraa19](https://github.com/rudraa19)
* [henilmalaviya](https://github.com/henilmalaviya)
* [Kaushal-00](https://github.com/Kaushal-00)
* [BeathovenGala](https://github.com/BeathovenGala)
