# CodeBleed

**CodeBleed** is a cybersecurity intelligence platform for modern codebases. It scans repositories, builds a graph of files, developers, dependencies, endpoints, and security findings, then surfaces hidden attack paths that traditional point-in-time scanners often miss.

Built for hackathon-style speed but designed with long-term extensibility in mind, CodeBleed combines repository ingestion, graph-based reasoning, and AI-assisted prioritization to help teams understand **where risk exists, why it matters, and what to fix first**.

---

## Why CodeBleed?

In fast-moving development environments, especially with AI-assisted coding, repositories grow quickly and security review often becomes reactive.

Most tools can flag isolated issues such as:
- exposed secrets
- vulnerable dependencies
- insecure endpoints
- risky commits

But real-world compromise usually happens through **connected weaknesses**, not isolated ones.

CodeBleed addresses that gap by modeling a repository as a **knowledge graph** and identifying exploitable relationships between:
- code files
- developers and commit history
- dependencies and CVEs
- endpoints and exposed surfaces
- findings that can combine into larger attack paths

---

## By the numbers

The security problem CodeBleed addresses is not theoretical. It is already visible in how modern software is being written and where risk is showing up:

- **46% of code** in files where GitHub Copilot was enabled was completed by Copilot; in Java, that number reached **61%**.[^1]
- **97% of surveyed developers** reported having used AI coding tools at work at some point.[^2]
- **39 million+ secrets** were leaked across GitHub in **2024 alone**.[^3]
- **45% of AI-generated code tasks** tested by Veracode introduced a known security flaw; in its Spring 2026 update, secure completion was still only **55%** overall.[^4][^5]
- Georgetown CSET found that **almost half** of code snippets produced by five LLMs contained bugs that could potentially lead to malicious exploitation.[^6]
- A USENIX study on package hallucinations found rates of **5.2% for commercial models** and **21.7% for open-source models**, including **205,474 unique hallucinated package names**.[^7]
- A 2026 large-scale study of AI-authored commits across real GitHub repositories identified **484,606 introduced issues** across **3,841 repositories**, based on **304,362 verified AI-authored commits** from **6,275 repositories**.[^8]

These numbers are exactly why CodeBleed focuses on more than isolated alerts. When AI-assisted development increases code volume, dependency sprawl, and review pressure, security issues stop being single findings and start becoming **connected attack paths**.

### What CodeBleed is built to quantify in a scan

CodeBleed helps make these risks visible by mapping and connecting:
- **secret exposure** (tokens, credentials, hardcoded secrets)
- **dependency risk** (vulnerable packages, CVEs, and risky third-party links)
- **attack surface** (dangerous endpoints and externally reachable components)
- **graph-connected attack paths** that show how multiple low-level findings can combine into a realistic exploit route

Rather than only saying **"a vulnerability exists,"** CodeBleed is designed to show **where it sits, what it connects to, and why it matters first**.

---

## What the platform does

CodeBleed helps teams:
- scan a GitHub repository or local codebase
- extract security-relevant entities and relationships
- assemble them into a graph structure in Neo4j
- identify possible attack paths across the repository
- prioritize findings based on context, connectivity, and severity
- provide AI-assisted explanations and remediation suggestions
- visualize the full security graph interactively

---

## Core idea

Traditional scanners answer:
> “What vulnerabilities exist?”

CodeBleed goes a step further and answers:
> “How can these issues connect into an actual attack route?”

That difference is what makes the system more useful for triage, demos, and future productization.

---

## Key features

### 1. Smart repository ingestion
- Accepts repository input from GitHub or local source
- Pulls code structure and metadata
- Captures developer and commit context where available

### 2. Security extraction
- Scans for secrets and sensitive patterns
- Identifies vulnerable dependencies
- Detects publicly exposed or risky surfaces
- Enriches dependency issues with public vulnerability intelligence

### 3. Graph assembly in Neo4j
- Converts extracted entities into nodes and relationships
- Builds a repository-centric knowledge graph
- Makes complex risk paths queryable and visualizable

### 4. Attack path discovery
- Uses graph traversal logic to find likely exploit routes
- Highlights chains of connected weaknesses rather than isolated alerts

### 5. AI-assisted synthesis
- Summarizes graph findings in plain English
- Explains why a path is risky
- Suggests prioritized remediation steps

### 6. Interactive visualization
- Displays nodes and relationships in a graph UI
- Makes it easy to demonstrate how code, developers, dependencies, and findings connect
- Supports risk storytelling during demos and reviews

---

## High-level architecture

```text
             +----------------------+
             |   GitHub / Local     |
             |     Repository       |
             +----------+-----------+
                        |
                        v
             +----------------------+
             |  Ingestion Pipeline  |
             +----------+-----------+
                        |
                        v
             +----------------------+
             | Security Extraction  |
             | secrets / deps / API |
             +----------+-----------+
                        |
                        v
             +----------------------+
             |   Graph Assembly     |
             |       Neo4j          |
             +----------+-----------+
                        |
          +-------------+-------------+
          |                           |
          v                           v
+----------------------+   +----------------------+
|  Attack Path Logic   |   |   AI Prioritization  |
+----------+-----------+   +----------+-----------+
           \                         /
            \                       /
             v                     v
              +-------------------+
              |   Frontend Graph  |
              | Visualization UI  |
              +-------------------+
```

---

## Tech stack

### Frontend
- React
- TypeScript
- Graph visualization library for relationship mapping

### Backend
- FastAPI
- Python
- Uvicorn

### Data / Graph layer
- Neo4j

### Security / intelligence
- Repository parsing and scanning pipeline
- Vulnerability enrichment from public sources
- AI reasoning layer for prioritization and explanation

---

## Project structure

```text
codebleed/
├── frontend/      # UI for scan submission, results, and graph visualization
├── backend/       # FastAPI services, scanning pipeline, graph logic, APIs
├── resources/     # Supporting assets, sample data, or local resources
└── README.md
```

This structure keeps the platform modular and makes it easier to extend individual layers independently.

---

## How it works

1. A user submits a GitHub repository URL or a local repository.
2. The backend ingests the codebase and collects metadata.
3. Security extraction services identify relevant issues and signals.
4. The system converts findings into graph nodes and edges.
5. Neo4j stores and connects these relationships.
6. Attack path logic traverses the graph to identify risky routes.
7. The AI layer summarizes the most important findings.
8. The frontend displays the results in an interactive graph view.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/DhruvvArora/codebleed.git
cd codebleed
```

### 2. Set up the backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Run the backend:

```bash
uvicorn main:app --reload --port 8000
```

### 3. Set up the frontend

```bash
cd ../frontend
npm install
npm run dev
```

### 4. Start Neo4j

Use either:
- Neo4j Desktop
- Neo4j Aura
- a local Docker setup

Make sure the backend can access the Neo4j instance through environment variables.

---

## Environment variables

Create a `.env` file for the backend and configure values similar to the following:

```env
GITHUB_TOKEN=your_github_token
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=your_password
AI_API_KEY=your_model_api_key
```

Notes:
- `GITHUB_TOKEN` is strongly recommended to avoid strict GitHub rate limits.
- If you are using a hosted Neo4j database, update the URI accordingly.
- Replace `AI_API_KEY` with the key used by your reasoning layer.

---

## Example workflow

### Submit a scan
A user provides a repository such as:

```text
https://github.com/example/project
```

### Backend processing
The system:
- clones or reads the repository
- extracts files, dependencies, and metadata
- scans for findings
- builds graph relationships
- runs attack path analysis

### Output
The frontend then shows:
- connected nodes and relationships
- severity-aware findings
- attack path explanations
- prioritized fixes

---

## Example use cases

CodeBleed can be useful for:
- hackathon demos
- security reviews of new projects
- repository risk exploration
- prioritizing fixes in fast-moving teams
- showing why a vulnerability matters in context
- developer education through graph-based explanations

---

## What makes it different

Many tools stop at scanning.

CodeBleed focuses on **security context**:
- not just *what* is wrong
- but *how* multiple issues connect
- and *which* fixes reduce the most risk first

That makes it especially valuable for:
- demo storytelling
- triage workflows
- attack-path-driven remediation
- visual security reasoning

---

## Current status

CodeBleed is currently a prototype / hackathon project and is designed to demonstrate:
- repository-to-graph transformation
- attack-path-centric security analysis
- explainable prioritization using AI
- interactive graph-based visualization

Future iterations can extend it into a fuller platform with:
- real-time rescans
- background job queues
- team dashboards
- scan history and comparisons
- policy-based risk scoring
- multi-repo intelligence

---

## Future improvements

Potential next steps include:
- stronger secret scanning heuristics
- richer dependency intelligence and CVE mapping
- better attack path ranking algorithms
- historical commit risk analysis
- developer ownership mapping
- improved graph filtering and search in the UI
- support for async scan pipelines and status polling
- exportable reports for security teams

---

## Demo talking points

When presenting CodeBleed, emphasize these three ideas:

### 1. Repositories are connected systems
A repo is not just a folder of files. It is a living network of people, code, dependencies, and exposures.

### 2. Real attacks follow paths
Attackers exploit chains, not isolated findings.

### 3. Visualization improves actionability
Seeing the path makes the risk easier to understand, explain, and fix.

---

## Challenges addressed

This project tackles several practical challenges:
- security findings are often noisy and disconnected
- repository context is difficult to understand quickly
- prioritization is hard when all alerts look equally urgent
- security demos often lack a strong visual reasoning layer

CodeBleed addresses these by combining graph intelligence with explainable summaries.

---

## Contributors

Built as a collaborative hackathon project.

- Dhruv Arora
- Pushkraj Kohok

---

## License

- MIT
- Apache 2.0
- Proprietary / Internal hackathon demo

---

## Closing note

CodeBleed is built around a simple belief:

**Security tools should not just list problems. They should help people understand risk as a connected story.**

That is the purpose of CodeBleed.

---

## References

[^1]: GitHub, [*How companies are boosting productivity with generative AI*](https://github.blog/ai-and-ml/generative-ai/how-companies-are-boosting-productivity-with-generative-ai/) (May 2023).
[^2]: GitHub, [*Survey: The AI wave continues to grow on software development teams*](https://github.blog/news-insights/research/survey-ai-wave-grows/) (Aug 2024).
[^3]: GitHub, [*GitHub found 39M secret leaks in 2024. Here's what we're doing to help*](https://github.blog/security/application-security/next-evolution-github-advanced-security/) (Apr 2025).
[^4]: Veracode, [*We Asked 100+ AI Models to Write Code. Here's How Many Failed Security Tests*](https://www.veracode.com/blog/genai-code-security-report/) (Jul 2025).
[^5]: Veracode, [*Spring 2026 GenAI Code Security Update: Despite Claims, AI Models Are Still Failing Security*](https://www.veracode.com/blog/spring-2026-genai-code-security/) (Mar 2026).
[^6]: Georgetown CSET, [*Cybersecurity Risks of AI-Generated Code*](https://cset.georgetown.edu/publication/cybersecurity-risks-of-ai-generated-code/) and [*Key Takeaways*](https://cset.georgetown.edu/wp-content/uploads/CSET-Key-Takeaways-Cybersecurity-Risks-of-AI-Generated-Code.pdf) (2024).
[^7]: Spracklen et al., [*We Have a Package for You! A Comprehensive Analysis of Package Hallucinations by Code Generating LLMs*](https://arxiv.org/abs/2406.10279) (USENIX Security 2025 / arXiv 2024).
[^8]: [*Debt Behind the AI Boom: A Large-Scale Empirical Study of AI-Generated Code in the Wild*](https://arxiv.org/html/2603.28592v1) (Mar 2026).

