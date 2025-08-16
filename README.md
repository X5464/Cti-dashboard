# 🛡️ CTI Dashboard - Cyber Threat Intelligence Portal

![CTI Dashboard](https://img.shields.io/badge/CTI-Dashboard-blue?style=for-the-badge&logo=security&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=flat-square&logo=python)
![React](https://img.shields.io/badge/React-18.2+-blue?style=flat-square&logo=react)
![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green?style=flat-square&logo=mongodb)


*(Insert high-quality screenshots or a concise animated GIF here demonstrating the dashboard's user interface and key functionalities. This is crucial for immediate visual understanding of the "Professional UI - Modern glass morphism design" and how the universal threat scanner, detailed reports, and dark theme appear in action.)*

## 📋 Overview

The CTI Dashboard is a comprehensive Cyber Threat Intelligence (CTI) portal designed to provide real-time threat analysis for IP addresses, domains, and URLs. By integrating with leading threat intelligence APIs such as VirusTotal and AbuseIPDB, this platform offers detailed security insights, empowering security professionals and enthusiasts with an intuitive tool for proactive threat detection and analysis. It aims to simplify the process of gathering and interpreting threat data, making advanced intelligence accessible.

## 🚀 Features

### Core Capabilities

  - 🌐 **Universal Threat Scanner** - Analyze IPs, domains, and URLs with a unified interface.
  - 🔍 **VirusTotal Integration** - Leverage over 60 security engines for comprehensive malware analysis.
  - 🛡️ **AbuseIPDB Intelligence** - Access community-driven abuse reports for enhanced IP reputation insights.
  - 📊 **Comprehensive Analysis** - Obtain detailed threat scoring and a breakdown of security findings.
  - 📈 **Historical Tracking** - Maintain a record of past scans with associated statistics for trend analysis.
  - 📱 **Responsive Design** - Enjoy a seamless user experience across various devices and screen sizes.

### Technical Features

  - ⚡ **Real-time Analysis** - Process and display live threat intelligence data efficiently.
  - 🎯 **Professional UI** - Experience a modern interface featuring a glass morphism design.
  - 📋 **Detailed Reports** - View individual security engine results for granular analysis.
  - 🔄 **Auto-deployment Ready** - Configured for easy integration with GitHub-based deployment pipelines.
  - 🎨 **Dark Theme** - Utilize an eye-friendly dark mode for comfortable viewing in low-light environments.

## 🚀 Live Demo

Experience the CTI Dashboard live: [https://cti-dashboard-frontend.onrender.com/](https://cti-dashboard-frontend.onrender.com/)

*Note: The live demo may occasionally be inaccessible due to hosting provider limitations or maintenance. For a visual overview, please refer to the "Visual Showcase" section above.*

## 🛠️ Tech Stack

**Backend:**

  - **Flask (Python)** - Robust REST API server for handling requests and data processing.
  - **MongoDB Atlas** - Cloud-hosted NoSQL database for scalable data storage.
  - **VirusTotal API** - External API for advanced malware and threat analysis.
  - **AbuseIPDB API** - External API for IP reputation and abuse reporting.

**Frontend:**

  - **React 18** - Modern JavaScript library for building dynamic user interfaces.
  - **Tailwind CSS** - Utility-first CSS framework for rapid and consistent styling.
  - **Axios** - Promise-based HTTP client for efficient API communication.
  - **Chart.js** - Flexible JavaScript charting library for data visualization.

## ⚙️ Installation

To set up and run the CTI Dashboard locally, follow these steps:

### Prerequisites

Ensure you have the following installed on your system:

  * **Python 3.8+**
  * **Node.js** (LTS version recommended)
  * **npm** or **Yarn**

### 1\. Clone the Repository

Begin by cloning the project repository to your local machine:bash
git clone [https://github.com/X5464/Cti-dashboard.git](https://www.google.com/search?q=https://github.com/X5464/Cti-dashboard.git)
cd Cti-dashboard

````

### 2. Backend Setup (Flask)

Navigate into the `backend` directory:

```bash
cd backend
````

Create a Python virtual environment and activate it:

```bash
python -m venv venv
# On Windows:.\venv\Scripts\activate
# On macOS/Linux: source venv/bin/activate
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

**Configure Environment Variables:**
Create a `.env` file in the `backend` directory. This file will store your API keys and database connection string.

```dotenv
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
MONGO_URI=your_mongodb_atlas_connection_string
```

  * **VirusTotal API Key:** Obtain your API key from the(https://www.virustotal.com/gui/join-us). Be aware that public API keys have rate limits (e.g., a certain number of requests per minute and per day). Exceeding these limits may result in temporary blocking of your key.
  * **AbuseIPDB API Key:** Obtain your API key from the(https://www.abuseipdb.com/register). This API also has usage limits, so manage your requests accordingly.
  * **MongoDB Atlas Connection String:** The project utilizes **MongoDB Atlas (Free Tier)** for its cloud database. You can set up a free cluster on the(https://www.mongodb.com/cloud/atlas/register). Ensure your connection string includes your database name and credentials.

### 3\. Frontend Setup (React)

Navigate back to the root directory of the project and then into the `frontend` directory:

```bash
cd../frontend
```

Install the Node.js dependencies:

```bash
npm install # or yarn install
```

**Configure Environment Variables:**
Create a `.env` file in the `frontend` directory.

```dotenv
REACT_APP_BACKEND_URL=http://localhost:5000 # Or your deployed backend URL if applicable
```

## 🚀 Usage

Once both the backend and frontend are set up, you can run the CTI Dashboard:

### 1\. Start the Backend Server

From the `backend` directory (with your virtual environment activated):

```bash
flask run
```

The backend server will typically run on `http://localhost:5000`.

### 2\. Start the Frontend Application

From the `frontend` directory:

```bash
npm start # or yarn start
```

The frontend application will open in your default web browser, usually at `http://localhost:3000`.

You can now use the dashboard to:

![1](https://github.com/user-attachments/assets/d0e0b355-71c4-439a-b37e-48270a41cc17)

![2](https://github.com/user-attachments/assets/c8bff3b5-019d-4735-ba74-7e008a976815)
![3](https://github.com/user-attachments/assets/c9236df6-0b69-4bfa-9d3f-574cfe0cf589)



  * Enter an IP address, domain, or URL into the universal threat scanner.
  * View detailed analysis reports from VirusTotal and AbuseIPDB.
  * Track historical scan data and statistics.

## 📦 Project Structure

The project is organized into `backend` (Flask API) and `frontend` (React application) directories.
For a detailed view of the repository structure, visit the GitHub repository: [https://github.com/X5464/Cti-dashboard](https://github.com/X5464/Cti-dashboard)

## 🤝 Contributing

We welcome contributions to the CTI Dashboard\! If you'd like to contribute, please follow these steps:

1.  **Fork** the repository.
2.  **Create a new branch** for your feature or bug fix: `git checkout -b feature/YourFeatureName`
3.  **Make your changes** and commit them with a clear, concise message: `git commit -m 'feat: Add new feature'`
4.  **Push** your changes to your forked repository: `git push origin feature/YourFeatureName`
5.  **Open a Pull Request** to the `main` branch of this repository.

Please ensure your code adheres to the project's coding standards and includes relevant tests. For more detailed guidelines, please refer to our(CONTRIBUTING.md) file (if available).

## 📄 License

This project is licensed under the MIT License - see the(LICENSE) file for details.

## 🙏 Acknowledgments

  * VirusTotal for providing comprehensive threat intelligence data.
  * AbuseIPDB for community-driven IP reputation data.
  * The Flask, React, MongoDB, Tailwind CSS, Axios, and Chart.js communities for their excellent tools and support.

## 📧 Contact

For any questions, feedback, or inquiries, please feel free to open an issue in this repository or contact the project maintainer directly.

```
```



