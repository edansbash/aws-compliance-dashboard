# AWS Compliance Dashboard

## Project Overview

A local Docker Compose application for scanning AWS resources across single or multi-account environments against custom compliance rules. Provides a dashboard for viewing compliance status, managing rule exceptions, and remediating non-compliant resources.

## Tech Stack

- **Frontend**: React with TypeScript, Vite, TailwindCSS
- **API**: Python FastAPI
- **Database**: PostgreSQL
- **Infrastructure**: Docker Compose (local development)
- **AWS SDK**: boto3 for Python

## Project Structure

```
aws-compliance-dashboard/
├── docker-compose.yml
├── frontend/                 # React frontend
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── services/
│   │   └── types/
│   └── Dockerfile
├── api/                      # FastAPI backend
│   ├── app/
│   │   ├── routers/
│   │   ├── services/
│   │   ├── models/
│   │   ├── rules/
│   │   └── scanners/
│   └── Dockerfile
├── db/                       # Database migrations
│   └── migrations/
└── docs/
    └── design.md
```

## Key Concepts

- **Rules**: Compliance checks defined in Python, each with an evaluation function and optional remediation
- **Scans**: Point-in-time execution of rules against AWS resources
- **Findings**: Individual compliance violations discovered during scans
- **Exceptions**: User-defined exclusions for specific resources or entire rules with justification

## AWS Credentials

The application expects AWS credentials to be provided via:
1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
2. AWS credentials file mounted into the container
3. IAM role assumption for cross-account access

## Default Scan Regions

US regions by default:
- us-east-1, us-east-2
- us-west-1, us-west-2

## Development Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Rebuild after code changes
docker-compose up -d --build

# Run database migrations
docker-compose exec api alembic upgrade head
```

## API Conventions

- RESTful endpoints under `/api/v1/`
- JSON request/response bodies
- Standard HTTP status codes
- Pagination via `?page=1&per_page=20`

## Code Style

- Python: Black formatter, type hints required
- TypeScript: Prettier, strict mode enabled
- All functions should have docstrings/JSDoc comments
