# 5G Core Security Assessment

This repository contains the **source code, documentation, and artifacts** for the research project “5G Core Security Assessment in Kubernetes Goat Environment”.

## Contents

| Path | Description |
|------|-------------|
| `docs/public/` | Rendered markdown report, network-policy manifests, scripts & assets |
| `docs/src/`    | React + Vite front-end that visualises the assessment (attack scenarios, mitigations, docs download) |
| `docs/`        | Front-end configuration files (Vite, Tailwind, ESLint, etc.) |

## Running Locally

```bash
# clone repository
git clone https://github.com/LuisAzofra/5G-Core-Security-Assessment.git
cd 5G-Core-Security-Assessment/docs

# install deps
npm install

# start dev server
npm run dev
```

The site will be available on `http://localhost:5173` (or the port indicated by Vite).

## Production Build

```bash
npm run build   # generates static assets in docs/dist
```

The project is automatically deployed to **GitHub Pages** from the `main` branch.

## Author

Made by **Luis Azofra Begara**
