# appsec-signup

A secure Dockerized Flask application for user registration with email verification, advanced password policies, and CAPTCHA protection.

## Features

### Functional Requirements
- **User Registration**: Complete signup form with email, username, password, and phone number
- **Client-Side Validation**: Real-time form validation with helpful instructions
- **Server-Side Validation**: Comprehensive input validation with clear error messages
- **Password Strength Meter**: Visual indicator with requirements checklist
- **Advanced Password Policy**: Requires uppercase, lowercase, digit, and special character
- **Email Domain Restrictions**: Configurable whitelist/blacklist for email domains
- **CAPTCHA (reCAPTCHA)**: Google reCAPTCHA integration to prevent automated abuse
- **Account Activation**: Email-based account activation with secure tokens
- **HTTPS Enforcement**: Production-ready HTTPS with Flask-Talisman

### Non-Functional Requirements
- **Secure Password Handling**: Argon2id hashing with salting and peppering
- **PostgreSQL Database**: Production-ready database with proper schema
- **Docker Support**: Full containerization with docker-compose

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
   
   # Optional: Password pepper for additional security
   PASSWORD_PEPPER=your-secret-pepper
   
   # Optional: reCAPTCHA keys (get from https://www.google.com/recaptcha/admin)
   RECAPTCHA_SITE_KEY=your-recaptcha-site-key
   RECAPTCHA_SECRET_KEY=your-recaptcha-secret-key
   
   # Optional: Email domain restrictions
   EMAIL_DOMAIN_WHITELIST=company.com,partner.org
   EMAIL_DOMAIN_BLACKLIST=tempmail.com,throwaway.com,mailinator.com
   
   # Optional: Application settings
   APP_URL=https://your-domain.com
   ACTIVATION_TOKEN_EXPIRY_HOURS=24
   FORCE_HTTPS=true
   ```

3. Start the application:
   ```bash
   docker compose up -d
   ```

4. Open your browser and navigate to `http://localhost:5000`

## Configuration

Environment variables (configure in `.env` file or environment):

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `SECRET_KEY` | Flask secret key for session management | Yes | - |
| `POSTGRES_USER` | PostgreSQL username | No | postgres |
| `POSTGRES_PASSWORD` | PostgreSQL password | No | postgres |
| `POSTGRES_DB` | PostgreSQL database name | No | signup_db |
| `PASSWORD_PEPPER` | Additional secret for password hashing | No | (empty) |
| `RECAPTCHA_SITE_KEY` | Google reCAPTCHA site key | No | (empty - CAPTCHA disabled) |
| `RECAPTCHA_SECRET_KEY` | Google reCAPTCHA secret key | No | (empty - CAPTCHA disabled) |
| `EMAIL_DOMAIN_WHITELIST` | Comma-separated allowed email domains | No | (all allowed) |
| `EMAIL_DOMAIN_BLACKLIST` | Comma-separated blocked email domains | No | tempmail.com,... |
| `ACTIVATION_TOKEN_EXPIRY_HOURS` | Hours until activation token expires | No | 24 |
| `APP_URL` | Base URL for activation links | No | http://localhost:5000 |
| `FORCE_HTTPS` | Enable HTTPS enforcement | No | false |

## Database Schema

### Users Table
```sql
Table Users {
  email             varchar(255) [pk, not null, unique]
  username          varchar(255) [not null, unique]
  password_hash     varchar(255) [not null]  -- Argon2id hash
  phone_number      varchar(50)
  is_activated      boolean [not null, default: false]
}
```

### ActivationTokens Table
```sql
Table ActivationTokens {
  id               integer [pk, autoincrement]
  email            varchar(255) [not null, fk -> Users.email]
  activation_token varchar(255) [not null, unique]  -- SHA256 hash of UUID
  expires_at       datetime [not null]
}
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Display signup form |
| `/` | POST | Process registration |
| `/success` | GET | Show registration success message |
| `/signup/activate` | GET | Activate account with token |

## Project Structure

```
.
├── app.py              # Main Flask application with routes and validation
├── config.py           # Configuration settings
├── models.py           # Database models (User, ActivationToken)
├── templates/
│   ├── signup.html     # Signup form with password strength meter
│   ├── success.html    # Registration success page
│   └── activation.html # Account activation result page
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

- **Argon2id Password Hashing**: Modern, memory-hard password hashing algorithm with salting
- **Password Pepper**: Optional server-side secret for additional security
- **Password Policy**: Enforces strong passwords (8+ chars, mixed case, digit, special char)
- **reCAPTCHA**: Google reCAPTCHA v2 to prevent automated registration abuse
- **Email Domain Restrictions**: Whitelist/blacklist email domains
- **Account Activation**: Time-limited activation tokens prevent unverified accounts
- **Token Security**: Activation tokens are hashed (SHA256) in database, expire after 24 hours
- **HTTPS Enforcement**: Flask-Talisman with HSTS headers (production)
- **Input Validation**: Server-side validation for all inputs
- **SQL Injection Prevention**: SQLAlchemy ORM
- **XSS Protection**: Jinja2 auto-escaping
- **CSRF Protection**: Flask flash messages with secure sessions

## Sequence Diagrams

### User Registration Flow
1. User submits registration form
2. Server validates input (CAPTCHA, email, username, password, phone)
3. Server creates User record (is_activated=false)
4. Server generates activation token
5. Server sends activation email (integration required)
6. User receives success message

### Account Activation Flow
1. User clicks activation link with token
2. Server finds token in database
3. Server verifies token not expired
4. Server sets user's is_activated to true
5. Server deletes used token
6. User sees activation success message