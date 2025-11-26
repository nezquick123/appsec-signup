# appsec-signup

A Dockerized Flask application with Jinja2 templates that provides a signup form connecting to a PostgreSQL database.

## Features

- User signup form with validation
- PostgreSQL database integration
- Password hashing using Werkzeug
- Input validation for username, email, and password
- Responsive UI with Jinja2 templates
- Docker containerization with docker-compose

## Prerequisites

- Docker
- Docker Compose

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/nezquick123/appsec-signup.git
   cd appsec-signup
   ```

2. Start the application:
   ```bash
   docker compose up -d
   ```

3. Open your browser and navigate to `http://localhost:5000`

## Configuration

Environment variables can be set in docker-compose.yml or via a `.env` file:

- `DATABASE_URL`: PostgreSQL connection string (default: `postgresql://postgres:postgres@db:5432/signup_db`)
- `SECRET_KEY`: Flask secret key for session management

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

3. Set the database URL:
   ```bash
   export DATABASE_URL="postgresql://user:password@localhost:5432/signup_db"
   ```

4. Run the application:
   ```bash
   python app.py
   ```

## Security Features

- Password hashing using Werkzeug's secure hashing functions
- Input validation for all form fields
- SQL injection prevention via SQLAlchemy ORM
- XSS protection via Jinja2's auto-escaping