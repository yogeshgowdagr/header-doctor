# HeaderDoctor

A web tool designed to help developers manage and maintain HTTP headers in their applications. Analyze website security headers, get recommendations, and generate server-specific configurations.

## Features

- **Header Analysis**: Fetches and analyzes HTTP security headers from any website
- **Security Scoring**: Provides a security score based on OWASP recommendations
- **Recommendations**: Suggests missing headers with explanations
- **Server Configurations**: Generates ready-to-use configurations for NGINX, Apache, and IIS
- **Caching**: Uses Redis for fast response caching
- **Responsive UI**: Modern, mobile-friendly interface similar to securityheaders.com

## Setup

### Prerequisites
- Python 3.10+
- Redis server
- WSL Ubuntu 24 (if on Windows)

### Installation

1. **Install Redis** (WSL Ubuntu):
   ```bash
   sudo apt update && sudo apt install -y redis-server
   sudo systemctl start redis-server
   sudo systemctl enable redis-server
   ```

2. **Install Python dependencies**:
   ```bash
   python3 -m pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python3 app.py
   ```

4. **Access the application**:
   Open your browser and go to `http://localhost:5000`

## Usage

1. Enter a website URL in the input field
2. Click "Scan Headers" to analyze the website
3. View the security score and detailed analysis
4. Check recommendations for missing headers
5. Generate server-specific configurations for implementing missing headers

## Security Headers Analyzed

- **Strict-Transport-Security**: Forces HTTPS connections
- **Content-Security-Policy**: Prevents XSS attacks
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME type sniffing
- **Referrer-Policy**: Controls referrer information
- **Permissions-Policy**: Controls browser features and APIs

## Project Structure

```
headers-application/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── .env                  # Environment variables
├── templates/
│   └── index.html        # Main HTML template
├── static/
│   ├── css/
│   │   └── style.css     # Styling
│   └── js/
│       └── app.js        # Frontend JavaScript
└── INSTRUCTIONS.md       # Project instructions
```

## API Endpoints

- `GET /` - Main application page
- `POST /analyze` - Analyze website headers
- `POST /config` - Generate server configuration

## Technologies Used

- **Backend**: Python (Flask)
- **Frontend**: HTML, CSS, JavaScript
- **Caching**: Redis
- **HTTP Requests**: Python requests library

## Contributing

Feel free to contribute by opening issues or submitting pull requests for improvements and new features.

## License

This project is open source and available under the MIT License.