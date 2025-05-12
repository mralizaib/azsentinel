import requests
import logging
import json
from config import Config
from urllib3.exceptions import InsecureRequestWarning
import urllib3

# Suppress insecure HTTPS request warnings if verify is set to False
if not Config.WAZUH_VERIFY_SSL:
    urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger(__name__)

class WazuhAPI:
    def __init__(self):
        self.base_url = Config.WAZUH_API_URL
        self.username = Config.WAZUH_API_USER
        self.password = Config.WAZUH_API_PASSWORD
        self.verify_ssl = Config.WAZUH_VERIFY_SSL
        self.token = None
        
    def _get_token(self):
        """Get authentication token from Wazuh API"""
        try:
            auth_url = f"{self.base_url}/security/user/authenticate"
            response = requests.post(
                auth_url,
                auth=(self.username, self.password),
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                self.token = response.json()['data']['token']
                return True
            else:
                logger.error(f"Authentication failed. Status code: {response.status_code}, Response: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Error while authenticating with Wazuh API: {str(e)}")
            return False
    
    def _make_request(self, endpoint, method="GET", params=None, data=None):
        """Make a request to the Wazuh API"""
        if not self.token and not self._get_token():
            return {"error": "Authentication failed"}
        
        url = f"{self.base_url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, params=params, verify=self.verify_ssl)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, params=params, data=json.dumps(data), verify=self.verify_ssl)
            elif method.upper() == "PUT":
                response = requests.put(url, headers=headers, params=params, data=json.dumps(data), verify=self.verify_ssl)
            elif method.upper() == "DELETE":
                response = requests.delete(url, headers=headers, params=params, verify=self.verify_ssl)
            else:
                return {"error": f"Unsupported HTTP method: {method}"}
            
            # Handle 401 Unauthorized - Token may have expired
            if response.status_code == 401:
                if self._get_token():  # Try to get a new token
                    return self._make_request(endpoint, method, params, data)  # Retry the request
                else:
                    return {"error": "Unable to refresh authentication token"}
            
            return response.json()
        except Exception as e:
            logger.error(f"Error while making request to Wazuh API: {str(e)}")
            return {"error": str(e)}
    
    def get_agents(self, filters=None):
        """Get list of agents with optional filters"""
        params = filters or {}
        return self._make_request("/agents", params=params)
    
    def get_agent_details(self, agent_id):
        """Get details for a specific agent"""
        return self._make_request(f"/agents/{agent_id}")
    
    def get_rules(self, filters=None):
        """Get list of rules with optional filters"""
        params = filters or {}
        return self._make_request("/rules", params=params)
    
    def get_rule_details(self, rule_id):
        """Get details for a specific rule"""
        return self._make_request(f"/rules/{rule_id}")
    
    def get_alerts_summary(self):
        """Get summary of alerts"""
        return self._make_request("/overview/agents")
    
    def get_system_info(self):
        """Get Wazuh manager information"""
        return self._make_request("/manager/info")
    
    def get_manager_status(self):
        """Get Wazuh manager status"""
        return self._make_request("/manager/status")
        
    def get_disk_usage(self):
        """Get disk usage information from Wazuh manager"""
        try:
            # Get disk usage from manager/stats endpoint
            response = self._make_request("/manager/stats")
            
            if not response or 'data' not in response:
                return {'error': 'Failed to retrieve disk usage information'}
                
            # Extract disk usage data if available
            stats = response.get('data', {})
            disk_info = {}
            
            if isinstance(stats, dict) and 'disk_usage' in stats:
                disk_info = stats.get('disk_usage', {})
            else:
                # Try to get from system information
                sys_info = self.get_system_info()
                if isinstance(sys_info, dict) and isinstance(sys_info.get('data', {}), dict):
                    affected_items = sys_info.get('data', {}).get('affected_items', [])
                    if isinstance(affected_items, list) and len(affected_items) > 0:
                        for item in affected_items:
                            if isinstance(item, dict) and 'disk' in item:
                                disk_info = item.get('disk', {})
                                break
            
            return {'data': disk_info}
        except Exception as e:
            return {'error': str(e)}
            
    def get_service_status(self):
        """Get status of Wazuh services"""
        try:
            # Get service status from manager/status endpoint
            response = self._make_request("/manager/status")
            
            if not response or 'data' not in response:
                return {'error': 'Failed to retrieve service status information'}
                
            # Extract service status data
            service_data = response.get('data', {})
            services = []
            
            if isinstance(service_data, dict) and isinstance(service_data.get('affected_items', []), list):
                affected_items = service_data.get('affected_items', [])
                if affected_items and isinstance(affected_items[0], dict):
                    daemons = affected_items[0].get('daemons', {})
                    
                    # Format the service status data
                    if isinstance(daemons, dict):
                        for daemon_name, status in daemons.items():
                            services.append({
                                'name': daemon_name,
                                'status': str(status),
                                'running': str(status) == 'running'
                            })
                
            return {'data': services}
        except Exception as e:
            return {'error': str(e)}
