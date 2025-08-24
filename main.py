import os
import pandas as pd
from flask import Flask, render_template, redirect, url_for, session, request, jsonify
import msal
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# MSAL configuration
MSAL_CONFIG = {
    'client_id': os.environ.get('OAUTH_CLIENT_ID'),
    'authority': 'https://login.microsoftonline.com/common',
    'redirect_uri': os.environ.get('OAUTH_REDIRECT_URI', 'http://localhost:5100/auth/callback'),
    'scope': ['User.Read']
}

def get_redirect_uri():
    """Get the correct redirect URI for the current environment"""
    # Check if we're running in Docker (port 5100) or locally (port 5000)
    if os.environ.get('OAUTH_REDIRECT_URI'):
        return os.environ.get('OAUTH_REDIRECT_URI')
    
    # Determine if we should use HTTPS
    use_https = os.environ.get('USE_HTTPS', 'false').lower() == 'true'
    protocol = 'https' if use_https else 'http'
    
    # Check if we're running in Docker by looking for container environment
    if os.environ.get('DOCKER_CONTAINER') or os.path.exists('/.dockerenv'):
        # In Docker container, try to get host IP from environment or detect it
        host_ip = os.environ.get('HOST_IP')
        
        if not host_ip:
            # Try to detect host IP automatically
            try:
                import socket
                # Get the hostname and resolve it to IP
                hostname = socket.gethostname()
                host_ip = socket.gethostbyname(hostname)
                print(f"Auto-detected host IP: {host_ip}")
            except Exception as e:
                print(f"Could not auto-detect host IP: {e}")
                # Fallback to common Docker host IPs
                host_ip = 'host.docker.internal'  # Docker Desktop on Windows/Mac
                print(f"Using fallback host IP: {host_ip}")
        
        return f'{protocol}://{host_ip}:5100/auth/callback'
    
    # Default to localhost for local development
    return f'{protocol}://localhost:5100/auth/callback'

def load_excel_data():
    """Load data from devices.xlsx file"""
    try:
        df = pd.read_excel('devices.xlsx')
        return df.to_dict('records')
    except Exception as e:
        print(f"Error loading Excel file: {e}")
        return []

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    devices_data = load_excel_data()
    return render_template('dashboard.html', devices=devices_data, user=session['user'])

@app.route('/login')
def login():
    if 'user' in session:
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/auth/microsoft')
def microsoft_auth():
    """Initiate Microsoft OAuth flow using MSAL"""
    try:
        # Create MSAL application
        msal_app = msal.PublicClientApplication(
            MSAL_CONFIG['client_id'],
            authority=MSAL_CONFIG['authority']
        )
        
        # Get dynamic redirect URI
        redirect_uri = get_redirect_uri()
        print(f"Using redirect URI: {redirect_uri}")
        
        # Generate authorization URL
        auth_url = msal_app.get_authorization_request_url(
            MSAL_CONFIG['scope'],
            redirect_uri=redirect_uri,
            state=app.secret_key  # Use secret key as state for security
        )
        
        return redirect(auth_url)
        
    except Exception as e:
        print(f"Error initiating OAuth flow: {e}")
        return redirect(url_for('login'))

@app.route('/auth/callback')
def microsoft_callback():
    """Handle OAuth callback from Microsoft"""
    try:
        # Get authorization code from callback
        auth_code = request.args.get('code')
        state = request.args.get('state')
        
        if not auth_code:
            print("No authorization code received")
            return redirect(url_for('login'))
        
        # Validate state parameter
        if state != app.secret_key:
            print("Invalid state parameter")
            return redirect(url_for('login'))
        
        # Create MSAL application
        msal_app = msal.PublicClientApplication(
            MSAL_CONFIG['client_id'],
            authority=MSAL_CONFIG['authority']
        )
        
        # Get dynamic redirect URI
        redirect_uri = get_redirect_uri()
        
        # Exchange authorization code for access token
        result = msal_app.acquire_token_by_authorization_code(
            auth_code,
            MSAL_CONFIG['scope'],
            redirect_uri=redirect_uri
        )
        
        if 'error' in result:
            print(f"Token acquisition error: {result.get('error_description', 'Unknown error')}")
            return redirect(url_for('login'))
        
        # Get user info using Microsoft Graph API
        access_token = result['access_token']
        user_info = get_user_info_from_graph(access_token)
        
        if user_info:
            session['user'] = user_info
            return redirect(url_for('index'))
        else:
            print("Failed to get user info")
            return redirect(url_for('login'))
            
    except Exception as e:
        print(f"OAuth callback error: {e}")
        return redirect(url_for('login'))

def get_user_info_from_graph(access_token):
    """Get user information from Microsoft Graph API"""
    try:
        import requests
        
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        # Get user profile from Microsoft Graph
        response = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers=headers
        )
        
        if response.status_code == 200:
            user_data = response.json()
            return {
                'email': user_data.get('mail') or user_data.get('userPrincipalName', ''),
                'name': user_data.get('displayName', ''),
                'picture': None  # MSAL doesn't provide profile picture by default
            }
        else:
            print(f"Graph API error: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"Error getting user info from Graph: {e}")
        return None

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/api/devices')
def api_devices():
    if 'user' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    devices_data = load_excel_data()
    return jsonify(devices_data)

def get_ssl_context():
    """Get SSL context if HTTPS is enabled"""
    use_https = os.environ.get('USE_HTTPS', 'false').lower() == 'true'
    
    if not use_https:
        return None
    
    # Check for custom SSL certificate paths
    cert_file = os.environ.get('SSL_CERT_FILE', 'cert.pem')
    key_file = os.environ.get('SSL_KEY_FILE', 'key.pem')
    
    # Check if certificate files exist
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print(f"Using SSL certificates: {cert_file}, {key_file}")
        return (cert_file, key_file)
    
    # Try to create self-signed certificate for development
    try:
        print("SSL certificates not found. Creating self-signed certificates for development...")
        create_self_signed_cert()
        if os.path.exists('cert.pem') and os.path.exists('key.pem'):
            return ('cert.pem', 'key.pem')
    except Exception as e:
        print(f"Failed to create self-signed certificates: {e}")
        print("Falling back to HTTP...")
        return None
    
    return None

def create_self_signed_cert():
    """Create self-signed SSL certificate for development"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        import datetime
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Dev"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Dev"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Dev Org"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate and key to files
        with open('cert.pem', 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open('key.pem', 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        print("Self-signed SSL certificates created successfully!")
        
    except ImportError:
        print("cryptography package not available. Cannot create self-signed certificates.")
        print("Install with: pip install cryptography")
        print("Or provide your own SSL certificates using SSL_CERT_FILE and SSL_KEY_FILE environment variables.")
        raise

if __name__ == '__main__':
    # Check if OAuth credentials are configured
    if not os.environ.get('OAUTH_CLIENT_ID'):
        print("Warning: OAUTH_CLIENT_ID not found in environment variables.")
        print("Microsoft OAuth authentication will not work properly.")
        print("Please set this environment variable in your .env file.")
    
    # Check if redirect URI is configured
    if not os.environ.get('OAUTH_REDIRECT_URI'):
        print("Warning: OAUTH_REDIRECT_URI not set. Using auto-generated URI")
    
    # Display the redirect URI being used
    redirect_uri = get_redirect_uri()
    print(f"OAuth2 Redirect URI: {redirect_uri}")
    print(f"Make sure this URI is registered in your Azure App Registration!")
    
    # Get SSL context if HTTPS is enabled
    ssl_context = get_ssl_context()
    use_https = ssl_context is not None
    
    if use_https:
        print("Starting server with HTTPS enabled...")
        print(f"Access your application at: https://localhost:5100")
    else:
        print("Starting server with HTTP...")
        print(f"Access your application at: http://localhost:5100")
    
    app.run(
        debug=True, 
        host='0.0.0.0', 
        port=5100,
        ssl_context=ssl_context
    )
