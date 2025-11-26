# appsec-signup

A Dockerized Flask application with Jinja2 templates that provides a signup form connecting to a PostgreSQL database.

## Features

- User signup form with validation
- PostgreSQL database integration
- Password hashing using Werkzeug
- Input validation for username, email, and password
- Responsive UI with Jinja2 templates
- Docker containerization with docker-compose
- Production-ready with Gunicorn WSGI server

## Prerequisites

- Docker
- Docker Compose

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/nezquick123/appsec-signup.git
   cd appsec-signup
   ```

2. Create a `.env` file with required environment variables:
   ```bash
   SECRET_KEY=your-secure-random-secret-key
   POSTGRES_USER=postgres
   POSTGRES_PASSWORD=your-secure-database-password
   POSTGRES_DB=signup_db
   ```

3. Start the application:
   ```bash
   docker compose up -d
   ```

4. Open your browser and navigate to `http://localhost:5000`

## Configuration

Environment variables (required in `.env` file or environment):

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Flask secret key for session management | Yes |
| `POSTGRES_USER` | PostgreSQL username | No (default: postgres) |
| `POSTGRES_PASSWORD` | PostgreSQL password | No (default: postgres) |
| `POSTGRES_DB` | PostgreSQL database name | No (default: signup_db) |

## Project Structure

```
.
├── app.py              # Main Flask application
├── config.py           # Configuration settings
├── models.py           # Database models
├── templates/
│   ├── signup.html     # Signup form template
│   └── success.html    # Success page template
├── Dockerfile          # Docker image definition
├── docker-compose.yml  # Docker Compose configuration
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Development

To run the application locally without Docker:

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set environment variables:
   ```bash
   export DATABASE_URL="postgresql://user:password@localhost:5432/signup_db"
   export SECRET_KEY="your-secret-key"
   ```

4. Run the application:
   ```bash
   gunicorn --bind 0.0.0.0:5000 app:app
   ```

## Security Features

- Password hashing using Werkzeug's secure hashing functions
- Input validation for all form fields
- SQL injection prevention via SQLAlchemy ORM
- XSS protection via Jinja2's auto-escaping
- Required SECRET_KEY environment variable (no insecure defaults)
- Production WSGI server (Gunicorn)