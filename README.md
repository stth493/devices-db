# Devices DB - OAuth2 Authentication with Microsoft Azure AD

## Overview
A Flask web application for managing device databases with Microsoft OAuth2 authentication using MSAL library.

## Prerequisites
- Python 3.11+
- Docker (optional)
- Microsoft Azure App Registration

## Environment Variables
Create a `.env` file in the root directory with the following variables:

```env
# OAuth2 Configuration for Microsoft Azure AD
OAUTH_CLIENT_ID=your_azure_app_client_id_here
OAUTH_REDIRECT_URI=http://localhost:5100/auth/callback

# Flask Configuration
SECRET_KEY=your_flask_secret_key_here
```

## Azure App Registration Setup
1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to "Azure Active Directory" > "App registrations"
3. Create a new registration or use existing one
4. Add redirect URI: `http://localhost:5100/auth/callback`
5. Grant API permissions: `User.Read` (delegated)
6. Copy the Client ID to your `.env` file

## Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run locally (port 5000)
python main.py
```

## Docker Deployment
```bash
# Build Docker image
docker build -t devices-db .

# Run container
docker run -p 5100:5100 --env-file .env devices-db
```

## Port Configuration
- **Local Development**: Port 5000 (default)
- **Docker**: Port 5100 (must match OAuth2 redirect URI)

## OAuth2 Flow
1. User clicks "Login with Microsoft"
2. Redirected to Microsoft login
3. After authentication, redirected back to `/auth/callback`
4. User session created and redirected to dashboard

## Troubleshooting
- Ensure redirect URI in Azure matches exactly: `http://localhost:5100/auth/callback`
- Check that all environment variables are set in `.env` file
- Verify Docker container is running on port 5100
- Check console logs for OAuth2 debugging information