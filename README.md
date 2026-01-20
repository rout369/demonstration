
# 🔒 SecureAPI Demonstration

**Real-time Security Observability & Threat Detection System**

This project is a technical demonstration of a multi-layered security monitoring environment. It showcases the ability to monitor API performance, detect application-layer attacks, and integrate network-level IDS alerts into a single unified dashboard.

## 🚀 Key Features

* **Live Traffic Monitoring**: Visualizes real-time API response times and flags performance anomalies.
* **Signature-Based Detection**: Identifies common malicious patterns such as SQL Injection attempts and Brute Force attacks.
* **Integrated IDS Alerts**: Features a dedicated mock Suricata server that generates network-layer security events (e.g., SSH scans, Trojan activity).
* **Interactive Simulations**: Includes a built-in attack simulator to trigger and verify detection rules for DDoS, SQLi, and authentication failures.

## 🛠️ System Components

1. **Monitoring Backend (`server.js`)**: An Express.js server that handles security logic, metric collection, and event logging.
2. **Network IDS Simulator (`suricata-server.js`)**: A secondary service providing simulated network-level security telemetry.
3. **Security Dashboard (`dashbord.html`)**: A real-time interface built with Chart.js and Axios for threat visualization.

## 🎯 Project Achievements

* **Full-Stack Visibility**: Engineered a system that correlates backend logs with frontend metrics to reduce manual monitoring effort.
* **Custom Detection Rules**: Implemented logic to detect SQLi payloads (e.g., `' OR '1'='1`) and track repetitive authentication failures.
* **Data Normalization**: Designed the dashboard to fetch and display data from multiple independent security sources simultaneously.

## 🧪 Installation & Usage

1. **Clone the Repository**:
```bash
git clone https://github.com/rout369/demonstration.git
cd demonstration

```


2. **Install Dependencies**:
```bash
npm install

```


3. **Run the Servers (Open two terminals)**:
* Terminal 1: `npm start`
* Terminal 2: `npm run ids`


4. **Launch Dashboard**: Open `http://localhost:5000` in your browser.

---
