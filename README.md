<div align="center">

![Pulse Banner](docs/assets/pulse.jpg)

# Pulse - Security Log Generator

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Astro](https://img.shields.io/badge/astro-%232C2052.svg?style=for-the-badge&logo=astro&logoColor=white)](https://astro.build/)
[![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)](https://python.org/)
[![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)](https://typescriptlang.org/)
[![TailwindCSS](https://img.shields.io/badge/tailwindcss-%2338B2AC.svg?style=for-the-badge&logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com/)

[![License: CC0-1.0](https://img.shields.io/badge/License-CC0%201.0-lightgrey.svg?style=for-the-badge)](http://creativecommons.org/publicdomain/zero/1.0/)
[![Security](https://img.shields.io/badge/Security-Testing-green.svg?style=for-the-badge)](#features)
[![SIEM](https://img.shields.io/badge/SIEM-Compatible-blue.svg?style=for-the-badge)](#destinations)
[![Generators](https://img.shields.io/badge/Generators-100+-orange.svg?style=for-the-badge)](#event-generation)
[![SDL](https://img.shields.io/badge/SDL-HEC-red.svg?style=for-the-badge)](https://www.sentinelone.com/)
[![SentinelOne](https://img.shields.io/badge/SentinelOne-Parsers-purple.svg?style=for-the-badge)](https://www.sentinelone.com/)

**Modern security event generation platform for testing SIEM systems, parsers, and security tools.**

*Generate realistic synthetic security events from 100+ vendors • Simulate sophisticated attack scenarios • Validate parser effectiveness*

</div>

---

## 🚀 Quick Start

### 📋 Prerequisites
- Node.js 18+ (for frontend)
- Python 3.9+ (for backend)
- Docker & Docker Compose (for infrastructure)

### ⚡ Development Setup

1. **🐳 Start Infrastructure**
```bash
cd infrastructure
docker-compose up -d
```

2. **🐍 Start Backend API**
```bash
cd src-backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
python start_api.py
```

3. **🎨 Start Frontend**
```bash
cd src-frontend
npm install
npm run dev
```

4. **🌐 Access the Application**
- Frontend: http://localhost:4321
- Backend API: http://localhost:8001
- API Docs: http://localhost:8001/api/v1/docs

## 📁 Project Structure

```
/pulse-project
├── docs/                    # Architecture and usage docs
├── infrastructure/          # Docker Compose for Postgres/Redis
├── src-frontend/            # Astro + Tailwind + Catppuccin
│   ├── src/
│   │   ├── components/      # UI Components
│   │   ├── layouts/         # AppLayout.astro
│   │   ├── pages/           # Astro routes
│   │   └── styles/          # Global CSS
│   └── package.json
├── src-backend/             # FastAPI + Event Generators
│   ├── app/                 # API application
│   ├── event_generators/    # 100+ security event generators
│   ├── scenarios/           # Attack simulation scenarios
│   ├── parsers/             # SentinelOne parser configurations
│   └── requirements.txt
├── .gitignore
└── README.md
```

## ✨ Key Features

<div align="center">

| 🎯 **Event Generation** | 🔥 **Attack Scenarios** | 📡 **Destinations** | 🎨 **Modern UI** |
|:---:|:---:|:---:|:---:|
| 100+ Security Vendors | APT Campaigns | SDL HEC | Astro + React Islands |
| Realistic Corporate Data | Insider Threats | Syslog TCP/UDP | Tailwind + Catppuccin |
| OCSF 1.1.0 Compliant | Multi-day Simulations | File Export | Real-time Progress |

</div>

## 🎯 Features

### Event Generation
- **100+ Generators**: Comprehensive coverage across security vendors
- **Realistic Data**: Corporate test data with proper field formatting
- **Multiple Formats**: JSON, syslog, CEF, and vendor-specific formats

### Attack Scenarios
- **APT Campaigns**: Multi-day sophisticated attack simulations
- **Insider Threats**: Employee-based attack patterns
- **Breach Scenarios**: Complete attack chain simulations

### Destinations
- **SDL HEC**: SentinelOne Data Lake HTTP Event Collector with batching and retry logic
- **Syslog**: TCP/UDP syslog server integration
- **File Export**: CSV, JSON, and raw log file generation

### Modern UI
- **Astro Framework**: Static-first with React Islands for interactivity
- **Tailwind CSS**: Utility-first styling with Catppuccin theme
- **Real-time Updates**: Live progress monitoring during generation

## 🔧 Configuration

### Environment Variables
```bash
# Backend API
API_HOST=0.0.0.0
API_PORT=8000
DATABASE_URL=postgresql://pulse:pulse_dev_password@localhost:5432/pulse

# Authentication (optional for development)
DISABLE_AUTH=true
API_KEYS_ADMIN=your-secure-api-key

# SDL HEC Configuration
SDL_WRITE_TOKEN=your-sdl-write-token
```

## 🏗️ Architecture

### Backend (Python/FastAPI)
- **Event Generators**: Domain-specific logic for 100+ security products
- **Attack Scenarios**: Temporal correlation and multi-platform simulation
- **API Layer**: RESTful endpoints with OpenAPI documentation
- **Database**: PostgreSQL for destinations and configuration

### Frontend (Astro/TypeScript)
- **Static Generation**: Pre-built pages for optimal performance
- **React Islands**: Interactive components where needed
- **Responsive Design**: Mobile-first with Catppuccin dark theme

### Infrastructure
- **PostgreSQL**: Primary database for application data
- **Redis**: Caching and session management
- **Docker**: Containerized development environment

## 🚀 Quick Status

| Service | Status | URL | Description |
|---------|--------|-----|-------------|
| 🎨 **Frontend** | ✅ Running | http://localhost:4321 | Modern Astro UI with Catppuccin theme |
| ⚡ **Backend API** | ✅ Running | http://localhost:8001 | FastAPI with 100+ generators |
| 📖 **API Docs** | ✅ Available | http://localhost:8001/api/v1/docs | Interactive OpenAPI documentation |
| 🗄️ **Database** | ✅ SQLite | `pulse.db` | Ready for PostgreSQL upgrade |

## 📚 Documentation

- [🔧 API Documentation](http://localhost:8001/api/v1/docs) - Interactive OpenAPI docs
- [📝 Generator Guide](docs/generators.md) - How to create new generators  
- [⚔️ Scenario Guide](docs/scenarios.md) - Attack scenario development
- [🚀 Deployment Guide](docs/deployment.md) - Production deployment
- [✅ Phase 1 Complete](docs/PHASE_1_COMPLETE.md) - Modernization progress

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes following the coding standards
4. Test your changes thoroughly
5. Submit a pull request

## 📄 License

This project is designed for defensive security testing and research purposes. Use responsibly and in accordance with your organization's security policies.

## 🆘 Support

- [GitHub Issues](https://github.com/your-org/pulse/issues) - Bug reports and feature requests
- [Discussions](https://github.com/your-org/pulse/discussions) - Community support and ideas

---

> [!NOTE]
> **Pulse** - Empowering security teams with realistic synthetic data for better testing and validation.