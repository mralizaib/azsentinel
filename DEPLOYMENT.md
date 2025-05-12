# AZ Sentinel X Docker Deployment Guide

This guide provides detailed instructions for deploying the AZ Sentinel X application in a local Docker environment using server address 10.144.90.95.

## Deployment Package

For convenience, all the necessary files for deployment have been packaged together. If you received the deployment package ZIP file, simply extract it and follow the instructions in this guide.

If you want to create a deployment package from the source code, you can use the provided script:

```bash
./scripts/create-package.sh
```

This will create a ZIP file containing all necessary deployment files that you can transfer to your server.

## Prerequisites

Before you begin, ensure you have:

1. Docker and Docker Compose installed on your system
2. Git installed (to clone the repository)
3. Access to a Wazuh API (using 10.144.90.95)
4. Access to OpenSearch (using 10.144.90.95)
5. OpenAI API key (for AI-powered analysis)
6. Email SMTP credentials (for alert notifications)

## Automated Installation (Recommended)

The easiest way to install AZ Sentinel X is using the provided installation script:

```bash
git clone <repository-url> azsentinel
cd azsentinel
chmod +x scripts/install.sh
./scripts/install.sh
```

The script will:
1. Check for Docker and Docker Compose
2. Ask for an installation directory (default: /opt/azsentinel)
3. Copy all necessary files
4. Create a .env file if one doesn't exist
5. Optionally set up a systemd service for easy management
6. Provide further instructions

After running the script, you'll need to:
1. Edit the .env file with your specific configuration
2. Start the application using systemd or make commands

## Manual Installation

If you prefer to install manually, follow these steps:

### Step 1: Clone the Repository

```bash
git clone <repository-url> azsentinel
cd azsentinel
```

### Step 2: Set Up Environment Variables

The application requires various environment variables to be configured for proper operation.

```bash
# Create .env file from example
cp .env.example .env
```

Open the `.env` file and update the following variables with your actual credentials:

```
# Database Configuration
POSTGRES_USER=azsentinel
POSTGRES_PASSWORD=azsentinel123  # Change this to a secure password
POSTGRES_DB=azsentinel

# Wazuh API Credentials
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=your_wazuh_password

# OpenSearch Credentials
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=your_opensearch_password

# OpenAI API Key (for AI analysis)
OPENAI_API_KEY=your_openai_api_key

# Email Configuration (for alerts)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_email_app_password

# Application Security
SESSION_SECRET=generate_a_strong_random_secret_key
```

## Step 3: Build and Start the Application

The provided Makefile simplifies the deployment process:

```bash
# Set up the environment, create necessary directories
make setup

# Build Docker containers
make build

# Start the application
make up
```

The application will be accessible at `http://10.144.90.95:5000`.

## Step 4: First-time Login

Once the application is running, you can log in with the default admin credentials:

- Username: `admin`
- Password: `admin123`

**Important**: Change the default password immediately after your first login.

## Step 5: Configure AZ Sentinel X

### Configure Alert Settings:

1. Log in as the admin user
2. Navigate to the "Alerts" section
3. Create a new alert configuration:
   - Specify email recipients
   - Select relevant severity levels (Critical, High, Medium, Low)
   - Set notification time
   - Choose fields to include in alerts

### Configure Reports:

1. Navigate to the "Reports" section
2. Create a new report configuration:
   - Set report format (PDF or HTML)
   - Configure schedule (daily, weekly, etc.)
   - Add email recipients
   - Select severity levels to include

### Configure AI Insights:

1. Navigate to the "AI Insights" section
2. Set up insight templates with specific fields for analysis
3. Choose the AI model type (OpenAI, DeepSeek, or Ollama)

## Management Commands

The Makefile includes several helpful commands for managing the application:

```bash
# View logs
make logs

# Check status of containers
make ps

# Stop the application
make down

# Remove all containers and volumes
make clean

# Show all available commands
make help
```

## Troubleshooting

### Connection Issues

If you encounter connection issues to Wazuh or OpenSearch:

1. Verify that your Wazuh API and OpenSearch credentials are correct in the `.env` file
2. Ensure that ports 55000 (Wazuh API) and 9200 (OpenSearch) are accessible from your Docker host
3. Check the application logs: `make logs`

### Database Errors

If you encounter database errors:

1. Ensure that PostgreSQL container is running: `docker-compose ps`
2. Check PostgreSQL logs: `docker-compose logs db`
3. Verify database credentials in the `.env` file

### Email Notification Issues

If email notifications are not being sent:

1. Verify SMTP credentials in `.env` file
2. Ensure your SMTP server allows connections from external applications
3. For Gmail, you may need to use an App Password instead of your regular password

### Setting Up Nginx as a Reverse Proxy (Optional)

For production environments, it's recommended to use Nginx as a reverse proxy:

```bash
# Install Nginx if not already installed
sudo apt update
sudo apt install nginx

# Copy the provided configuration
sudo cp scripts/nginx/azsentinel.conf /etc/nginx/sites-available/azsentinel

# Create symbolic link to enable the site
sudo ln -s /etc/nginx/sites-available/azsentinel /etc/nginx/sites-enabled/

# Test the configuration
sudo nginx -t

# Reload Nginx
sudo systemctl reload nginx
```

The included Nginx configuration (`scripts/nginx/azsentinel.conf`) provides:
- Reverse proxy to your AZ Sentinel X instance
- Proper header forwarding
- Increased upload size for reports
- Security headers
- Logging configuration

### System Health Check

A health check script is provided to verify the deployment and connections to required services:

```bash
# Load environment variables (if not using a login shell)
source .env

# Run the health check
./scripts/healthcheck.sh
```

The script checks:
- Docker service status
- Container status
- Database connectivity
- Web server responsiveness
- Wazuh API connectivity
- OpenSearch connectivity

Run this after installation and periodically to ensure all components are working correctly.

### Generating Secure Session Secret

For security, you should use a strong random string for the `SESSION_SECRET` environment variable.
A helper script is provided to generate this:

```bash
# Generate a new secret
./scripts/generate-secret.sh

# The script can also automatically update your .env file
```

## Security Considerations

1. Always change the default admin password after first login
2. Use strong passwords for all credentials in the `.env` file
3. Generate a secure random session secret using the provided script
4. Consider implementing network-level isolation for your Docker environment
5. Use HTTPS with a proper SSL certificate in production
6. Regularly update the application and its dependencies
7. Consider using a firewall to limit access to only necessary ports

## Backup and Maintenance

### Database Backup and Restore

The provided backup-restore script simplifies database management:

```bash
# Create a backup with timestamp (saved to backups/ directory)
./scripts/backup-restore.sh backup

# Create a backup with custom name
./scripts/backup-restore.sh backup custom_name.sql

# Restore from a backup
./scripts/backup-restore.sh restore backups/azsentinel_20250509_123045.sql
```

The script will:
- Check for running containers
- Create a backups directory if needed
- Prompt for confirmation before restoring
- Handle environment variables from .env file

For manual backup/restore:

```bash
# Manual backup
docker-compose exec db pg_dump -U azsentinel azsentinel > backup.sql

# Manual restore
cat backup.sql | docker-compose exec -T db psql -U azsentinel azsentinel
```

### Setting Up as a Systemd Service

For production environments, it's recommended to run AZ Sentinel X as a systemd service:

```bash
# Copy the service file
sudo cp scripts/azsentinel.service /etc/systemd/system/

# Edit the service file to point to your installation directory
sudo sed -i "s|WorkingDirectory=.*|WorkingDirectory=/path/to/your/installation|g" /etc/systemd/system/azsentinel.service

# Reload systemd
sudo systemctl daemon-reload

# Start the service
sudo systemctl start azsentinel

# Enable at boot
sudo systemctl enable azsentinel

# Check status
sudo systemctl status azsentinel
```

### Upgrading the Application

1. Pull the latest changes from the repository
2. Rebuild the Docker containers: `make build`
3. Restart the application: 
   - Using Make: `make down && make up`
   - Using systemd: `sudo systemctl restart azsentinel`

## Support and Resources

For additional support or questions, please refer to:

- Project documentation
- Wazuh official documentation: https://documentation.wazuh.com
- OpenSearch documentation: https://opensearch.org/docs