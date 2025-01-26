# Intrusion Detection System (IDS)

## **Introduction**

This project is a Django-based **Intrusion Detection System (IDS)** designed to monitor, analyze, and detect anomalies in network traffic. It uses machine learning for anomaly detection and provides a web interface for real-time monitoring, configuration, and analysis.

The IDS leverages the **[NSL-KDD Feature Extractor](https://github.com/Ate329/NSL-KDD-feature-extractor)** to extract NSL-KDD dataset-compatible features from live network traffic. The feature extractor is already included in this project and does not need to be downloaded separately.

The dataset used for training the machine learning model is the **[NSL-KDD Dataset](https://www.kaggle.com/datasets/hassan06/nslkdd/data)**.

**Currently the web interface is not working, any who can fix it can try to submit a PR for it. I'll try to work on a easy CLI for now**

## **Features**

1. **Real-Time Traffic Monitoring**
   - Capture live network traffic using `scapy`.
   - Extract detailed traffic features using the integrated [NSL-KDD Feature Extractor](https://github.com/Ate329/NSL-KDD-feature-extractor).

2. **Machine Learning Integration**
   - Uses a pre-trained Random Forest model trained on the NSL-KDD dataset.
   - Features are normalized using a pre-trained scaler.

3. **Web-Based Interface**
   - Interactive dashboard with metrics for total, normal, and anomaly packets.
   - Visualizations for protocol and flag distribution, and 24-hour traffic trends.

4. **Configurable Settings**
   - Select network interface.
   - Enable/disable internal traffic detection.
   - Set up email alerts for anomalies.

5. **Logs and Data Export**
   - View and download traffic logs.
   - Export network traffic data to CSV for offline analysis.

6. **Maintenance Tools**
   - Clear logs, database records, and traffic data.
   - Manage scaler and machine learning model files.

## **How It Works**

### **Workflow Diagram**

```
                      +------------------+
                      |   Network Traffic|
                      +------------------+
                               |
                               v
               +-------------------------------+
               |    Packet Capturing           |
               |  (Using Scapy Framework)      |
               +-------------------------------+
                               |
                               v
          +----------------------------------------+
          |    Feature Extraction                 |
          | (via Integrated NSL-KDD Feature Extractor) |
          +----------------------------------------+
                               |
                               v
          +----------------------------------------+
          |  Feature Scaling and Alignment         |
          |  (Using Pre-trained Scaler and Feature |
          |  Names)                                |
          +----------------------------------------+
                               |
                               v
          +----------------------------------------+
          |      Machine Learning Model            |
          |  (NSL-KDD Random Forest Classifier)    |
          +----------------------------------------+
                |                     |
         Normal Traffic        Anomalous Traffic
                |                     |
        +---------------+     +------------------+
        | Logs to CSV   |     |  Raise Alert      |
        | (traffic_data)|     | (Email Notification|
        +---------------+     +------------------+
                               |
                               v
          +----------------------------------------+
          |  Web Interface (Django Application)    |
          |  - Dashboard: Real-time Visualization  |
          |  - Logs: View Detailed Logs            |
          |  - Traffic: Analyze Captured Data      |
          |  - Settings: Configure IDS             |
          +----------------------------------------+
```

## **Setup**

### **Prerequisites**

- **Python 3.11** or later
- **Django Framework**
- **Scapy** for packet capturing
- **Joblib** for model and scaler management
- **Pandas** and **NumPy** for data processing

### **Installation**
   Download setup_and_run.py and run the file
   ```
   python setup_and_run.py
   ```

### **Manual Installation (not recommended)**
1. Clone the repository:
   ```
   git clone https://github.com/Ate329/IDS.git
   cd IDS
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Migrate the database:
   ```
   python ids_project/manage.py migrate
   ```

4. Start the development server:
   ```
   python ids_project/manage.py runserver
   ```

5. Access the application in your browser:
   ```
   http://127.0.0.1:8000
   ```

## **Usage**

### **Web Application Features**

1. **Dashboard**
   - Displays real-time metrics for total, normal, and anomaly packets.
   - Includes charts for protocol and flag distributions and a 24-hour traffic summary.

2. **Traffic Logs**
   - View network activity logs.
   - Download traffic data as a CSV file for offline analysis.

3. **Settings**
   - Select the network interface for traffic capture.
   - Enable or disable internal traffic detection.
   - Configure email settings for alerts.

4. **Maintenance Tools**
   - Clear logs, traffic data, or database records.
   - Reset or update the pre-trained scaler and machine learning model.

## **Dataset and Feature Extraction**

1. **Dataset**
   - The machine learning model was trained on the **[NSL-KDD Dataset](https://www.kaggle.com/datasets/hassan06/nslkdd/data)**, a widely used dataset for network intrusion detection research.

2. **Feature Extraction**
   - The integrated **[NSL-KDD Feature Extractor](https://github.com/Ate329/NSL-KDD-feature-extractor)** extracts features directly from live network traffic, ensuring compatibility with models trained on the NSL-KDD dataset.

## **Development Notes**

- The project integrates the **NSL-KDD Feature Extractor** for feature extraction, which is already included in this repository.
- Replace or update the machine learning model in `models/NSL-KDD-RF-model.joblib` to adapt to different datasets or requirements.

## **Contributing**

If you’d like to extend the functionality or report a bug, feel free to submit a pull request or open an issue.

## **License**

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
