import logging
import os
import json
import requests
from datetime import datetime, timedelta
from sqlalchemy import text
from app import db
from models import RetentionPolicy
from opensearch_api import OpenSearchAPI
from config import Config

logger = logging.getLogger(__name__)

class RetentionManager:
    def __init__(self):
        self.opensearch = OpenSearchAPI()
    
    def apply_retention_policy(self, policy_id=None):
        """
        Apply retention policy to clean up data
        
        Args:
            policy_id: Optional specific policy ID to apply, otherwise all enabled policies
            
        Returns:
            Dictionary with results summary
        """
        results = {
            'success': False,
            'policies_applied': 0,
            'errors': [],
            'details': []
        }
        
        try:
            # Get policies to apply
            if policy_id:
                policies = RetentionPolicy.query.filter_by(id=policy_id, enabled=True).all()
            else:
                policies = RetentionPolicy.query.filter_by(enabled=True).all()
            
            if not policies:
                results['errors'].append('No enabled retention policies found')
                return results
            
            # Apply each policy
            for policy in policies:
                result = self._apply_single_policy(policy)
                results['details'].append({
                    'policy_id': policy.id,
                    'policy_name': policy.name,
                    'status': 'success' if result['success'] else 'error',
                    'details': result
                })
                
                if result['success']:
                    # Update last run time
                    policy.last_run = datetime.utcnow()
                    db.session.commit()
                    results['policies_applied'] += 1
                else:
                    results['errors'].append(f"Policy {policy.name} (ID: {policy.id}): {result['error']}")
            
            results['success'] = len(results['errors']) == 0
            return results
            
        except Exception as e:
            logger.error(f"Error applying retention policies: {str(e)}")
            results['errors'].append(str(e))
            return results
    
    def _apply_single_policy(self, policy):
        """Apply a single retention policy"""
        result = {
            'success': False,
            'items_deleted': 0,
            'error': None
        }
        
        try:
            if policy.source_type == 'opensearch':
                result = self._apply_opensearch_policy(policy)
            elif policy.source_type == 'wazuh':
                result = self._apply_wazuh_policy(policy)
            elif policy.source_type == 'database':
                result = self._apply_database_policy(policy)
            else:
                result['error'] = f"Unknown source type: {policy.source_type}"
                
            return result
        except Exception as e:
            logger.error(f"Error applying policy {policy.name}: {str(e)}")
            result['error'] = str(e)
            return result
    
    def _apply_opensearch_policy(self, policy):
        """Apply retention policy to OpenSearch data"""
        result = {
            'success': False,
            'items_deleted': 0,
            'error': None
        }
        
        try:
            # Calculate retention date
            retention_date = datetime.utcnow() - timedelta(days=policy.retention_days)
            retention_date_str = retention_date.isoformat()
            
            # Build the query
            query = {
                "query": {
                    "range": {
                        "@timestamp": {
                            "lt": retention_date_str
                        }
                    }
                }
            }
            
            # Add severity filters if specified
            severity_levels = policy.get_severity_levels()
            rule_ids = policy.get_rule_ids()
            
            if severity_levels or rule_ids:
                query["query"] = {
                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "lt": retention_date_str
                                    }
                                }
                            }
                        ]
                    }
                }
                
                if severity_levels:
                    # Map severity levels to rule.level ranges
                    level_ranges = []
                    for level in severity_levels:
                        if level == 'critical':
                            level_ranges.append({"term": {"rule.level": 15}})
                        elif level == 'high':
                            level_ranges.append({"range": {"rule.level": {"gte": 12, "lt": 15}}})
                        elif level == 'medium':
                            level_ranges.append({"range": {"rule.level": {"gte": 7, "lt": 12}}})
                        elif level == 'low':
                            level_ranges.append({"range": {"rule.level": {"gte": 1, "lt": 7}}})
                    
                    if level_ranges:
                        query["query"]["bool"]["must"].append({"bool": {"should": level_ranges}})
                
                if rule_ids:
                    rule_id_terms = [{"term": {"rule.id": rule_id}} for rule_id in rule_ids]
                    if rule_id_terms:
                        query["query"]["bool"]["must"].append({"bool": {"should": rule_id_terms}})
            
            # Execute deletion by query
            delete_response = self.opensearch.client.delete_by_query(
                index=self.opensearch.index_pattern,
                body=query,
                refresh=True
            )
            
            result['success'] = True
            result['items_deleted'] = delete_response['deleted']
            result['details'] = delete_response
            
            return result
        except Exception as e:
            logger.error(f"Error applying OpenSearch retention policy: {str(e)}")
            result['error'] = str(e)
            return result
    
    def _apply_wazuh_policy(self, policy):
        """Apply retention policy to Wazuh data via API"""
        result = {
            'success': False,
            'items_deleted': 0,
            'error': None
        }
        
        try:
            # For Wazuh, we can only do retention on logs by calling their API
            # First authenticate
            auth_url = f"{Config.WAZUH_API_URL}/security/user/authenticate"
            
            # Skip SSL verification if configured
            verify = Config.WAZUH_VERIFY_SSL
            
            auth_headers = {
                'Content-Type': 'application/json'
            }
            
            auth_data = {
                'username': Config.WAZUH_API_USER,
                'password': Config.WAZUH_API_PASSWORD
            }
            
            auth_response = requests.post(
                auth_url,
                headers=auth_headers,
                json=auth_data,
                verify=verify
            )
            
            if auth_response.status_code != 200:
                result['error'] = f"Failed to authenticate with Wazuh API: {auth_response.text}"
                return result
            
            token = auth_response.json()['data']['token']
            
            # Now call the delete API
            headers = {
                'Content-Type': 'application/json',
                'Authorization': f"Bearer {token}"
            }
            
            # Calculate retention date
            retention_date = datetime.utcnow() - timedelta(days=policy.retention_days)
            
            # Wazuh uses different date format (YYYY-MM-DD)
            retention_date_str = retention_date.strftime('%Y-%m-%d')
            
            # Delete logs before retention date
            delete_url = f"{Config.WAZUH_API_URL}/manager/logs"
            
            params = {
                'olderThan': retention_date_str
            }
            
            delete_response = requests.delete(
                delete_url,
                headers=headers,
                params=params,
                verify=verify
            )
            
            if delete_response.status_code >= 200 and delete_response.status_code < 300:
                result['success'] = True
                result['details'] = delete_response.json()
                result['items_deleted'] = 1  # API doesn't provide count of deleted items
                return result
            else:
                result['error'] = f"Failed to delete Wazuh logs: {delete_response.text}"
                return result
                
        except Exception as e:
            logger.error(f"Error applying Wazuh retention policy: {str(e)}")
            result['error'] = str(e)
            return result
    
    def _apply_database_policy(self, policy):
        """Apply retention policy to database tables"""
        result = {
            'success': False,
            'items_deleted': 0,
            'error': None,
            'tables': []
        }
        
        try:
            # Calculate retention date
            retention_date = datetime.utcnow() - timedelta(days=policy.retention_days)
            
            # Tables with created_at columns that can be pruned
            tables_to_clean = [
                'ai_insight_result',
                'alert_config',
                'report_config',
                'ai_insight_template'
            ]
            
            total_deleted = 0
            
            for table in tables_to_clean:
                try:
                    # Delete records older than retention date
                    sql = text(f"DELETE FROM {table} WHERE created_at < :retention_date")
                    delete_result = db.session.execute(sql, {'retention_date': retention_date})
                    deleted_count = delete_result.rowcount
                    
                    result['tables'].append({
                        'table': table,
                        'deleted': deleted_count
                    })
                    
                    total_deleted += deleted_count
                except Exception as table_error:
                    logger.error(f"Error cleaning table {table}: {str(table_error)}")
                    result['tables'].append({
                        'table': table,
                        'error': str(table_error)
                    })
            
            # Commit all changes
            db.session.commit()
            
            result['success'] = True
            result['items_deleted'] = total_deleted
            
            return result
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error applying database retention policy: {str(e)}")
            result['error'] = str(e)
            return result