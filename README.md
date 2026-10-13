# CyberShield Frontend

CyberShield is a real-time network traffic analysis and threat detection dashboard.

## 🚀 Overview

This repository contains the frontend web interface for CyberShield, designed for monitoring network events, analyzing traffic flows, and visualizing threat intelligence metrics.

## 🛠️ Tech Stack

- **Vanilla HTML5, CSS3, JavaScript** (Modern ES6+)
- **Nginx** (Production reverse proxy & static file serving)
- **Responsive Dark Cyberpunk UI / Glassmorphic Design**

## 📁 Project Structure

```text
frontend/
├── index.html        # Main dashboard interface
├── app.js            # Dashboard logic, API integration, interactive charts
├── styles.css        # Responsive styling and design system
├── Dockerfile        # Container build definition
└── nginx.conf        # Nginx server configuration and reverse proxy
```

## 🏃 Getting Started

### Local Development
You can serve `index.html` using any local static file server:
```bash 
# Using Python
python -m http.server 3000

# Or using Node http-server
npx http-server -p 3000
```

### Docker
```bashcd "C:\Users\Charan sai\Documents\Codex\2026-10-06\go-x20\outputs\cybershield"
docker build -t cybershield-frontend .
docker run -p 3000:80 cybershield-frontend
```

Open [http://localhost:3000](http://localhost:3000) in your browser.


1