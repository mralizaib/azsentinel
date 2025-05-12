# AZ Sentinel X Quick Start Guide

This guide provides the essentials to quickly deploy and start using AZ Sentinel X in a local Docker environment.

## Step 1: Deploy with One Command

```bash
# Download the deployment package
unzip azsentinel-deployment-*.zip

# Run the automated installation script
cd azsentinel-deployment
chmod +x scripts/install.sh
./scripts/install.sh
```

## Step 2: Configure Environment

The installation script will prompt you to create a `.env` file. Ensure you set these key variables:

```
# Connection to Wazuh API
WAZUH_API_URL=https://10.144.90.95:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASSWORD=your_wazuh_password

# Connection to OpenSearch
OPENSEARCH_URL=https://10.144.90.95:9200
OPENSEARCH_USER=admin
OPENSEARCH_PASSWORD=your_opensearch_password

# OpenAI API key for AI analysis
OPENAI_API_KEY=your_openai_api_key

# Email for alerts
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
```

## Step 3: Start the Application

```bash
# If using Make
make up

# If using systemd
sudo systemctl start azsentinel
```

## Step 4: Access the Application

1. Open your browser and go to: `http://10.144.90.95:5000`
2. Login with default credentials: 
   - Username: `admin`
   - Password: `admin123`
3. **IMPORTANT:** Change the default password immediately after first login

## Step 5: Initial Configuration

### Setup Alert Notifications

1. Navigate to `Alerts Configuration` in the sidebar
2. Click `Create New Alert Configuration`
3. Set up:
   - Notification name
   - Email recipient(s)
   - Select severity levels (Critical, High, Medium, Low)
   - Configure notification time (24-hour format, e.g., `08:00`)
   - Select fields to include in email alerts

### Setup Reports

1. Navigate to `Reports Configuration` in the sidebar
2. Click `Create New Report`
3. Set up:
   - Report name
   - Select format (PDF or HTML)
   - Configure schedule (daily, weekly)
   - Set time of day for report generation (24-hour format)
   - Add email recipients
   - Select severity levels to include

### Try AI Insights

1. Navigate to `AI Insights` in the sidebar
2. Click `Create New Template`
3. Set up:
   - Name your template
   - Select AI model (OpenAI, DeepSeek, or Ollama)
   - Choose fields to analyze
4. Run an analysis on recent alerts

## Verify Deployment

Run the health check script to verify all components are working correctly:

```bash
source .env  # If needed in your shell
./scripts/healthcheck.sh
```

## Troubleshooting

- Check logs: `make logs` or `docker-compose logs`
- Verify database connection: `docker-compose exec db pg_isready`
- Restart application: `make down && make up`
- Check Wazuh API connection: `curl -k -u "$WAZUH_API_USER:$WAZUH_API_PASSWORD" https://10.144.90.95:55000/version`

For detailed troubleshooting and configuration information, refer to the full [DEPLOYMENT.md](DEPLOYMENT.md) documentation.