#!/usr/bin/env python3
# Copyright (c) 2026 Broadcom Inc. and/or its subsidiaries.
# All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

"""
Marker Sync Tool - Syncs markers from VirtualService to ApplicationProfile

This script:
1. Logs into the Avi controller
2. Retrieves all VirtualServices
3. Checks if markers are present on each VS
4. For each VS with markers, checks the associated ApplicationProfile
5. If the ApplicationProfile doesn't have the marker or has different values,
   updates the ApplicationProfile with the marker

Usage:
    python marker_sync_tool.py --controller <ip> --username <user> --password <pass> [--tenant <tenant>]

Example:
    python marker_sync_tool.py --controller 10.10.10.10 --username admin --password admin123 --tenant admin
"""

import argparse
import json
import logging
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional, Any

import requests
import urllib3

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
LOG_FILE = f"marker_sync_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class AviSession:
    """Simple Avi Controller API session handler."""
    
    def __init__(self, controller: str, username: str, password: str, 
                 tenant: str = "admin", api_version: str = "30.2.1", verify: bool = False):
        self.controller = controller
        self.username = username
        self.password = password
        self.tenant = tenant
        self.api_version = api_version
        self.verify = verify
        self.session = requests.Session()
        self.base_url = f"https://{controller}"
        self.headers = {
            "Content-Type": "application/json",
            "X-Avi-Version": api_version,
            "X-Avi-Tenant": tenant
        }
        self.csrf_token = None
        
    def login(self) -> bool:
        """Authenticate with the Avi controller."""
        login_url = f"{self.base_url}/login"
        login_data = {
            "username": self.username,
            "password": self.password
        }
        
        try:
            response = self.session.post(
                login_url, 
                json=login_data, 
                headers={"Content-Type": "application/json"},
                verify=self.verify
            )
            
            if response.status_code == 200:
                # Get CSRF token from cookies
                self.csrf_token = self.session.cookies.get("csrftoken")
                if self.csrf_token:
                    self.headers["X-CSRFToken"] = self.csrf_token
                    self.headers["Referer"] = self.base_url
                logger.info(f"Successfully logged into controller {self.controller}")
                return True
            else:
                logger.error(f"Login failed: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Connection error during login: {e}")
            return False
    
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Optional[Dict]:
        """Make a GET request to the API."""
        url = f"{self.base_url}/api/{endpoint}"
        try:
            response = self.session.get(
                url, 
                headers=self.headers, 
                params=params,
                verify=self.verify
            )
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"GET {endpoint} failed: {response.status_code} - {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"GET request error: {e}")
            return None
    
    def get_all_pages(self, endpoint: str, params: Optional[Dict] = None, page_size: int = 200) -> List[Dict]:
        """
        Fetch all items from a paginated endpoint.
        
        Args:
            endpoint: API endpoint (e.g., "virtualservice")
            params: Additional query parameters
            page_size: Number of items per page (default: 200)
        
        Returns:
            List of all items from all pages
        """
        all_results = []
        page = 1
        
        # Make a copy to avoid mutating the caller's dict
        query_params = dict(params) if params else {}
        query_params["page_size"] = page_size
        
        while True:
            query_params["page"] = page
            logger.info(f"Fetching {endpoint} page {page} (page_size={page_size})...")
            
            response = self.get(endpoint, params=query_params)
            if not response:
                logger.error(f"Failed to fetch {endpoint} page {page}")
                break
            
            results = response.get("results", [])
            all_results.extend(results)
            
            # Check if there's a next page
            next_page_url = response.get("next")
            count = response.get("count", 0)
            
            logger.info(f"  Page {page}: got {len(results)} items, total so far: {len(all_results)}, server count: {count}")
            
            # Stop if no next page URL or no results returned
            if not next_page_url:
                logger.info(f"  No 'next' URL in response, stopping pagination")
                break
            
            if len(results) == 0:
                logger.info(f"  Empty results, stopping pagination")
                break
            
            # Also stop if we've fetched all items based on count
            if count > 0 and len(all_results) >= count:
                logger.info(f"  Fetched all {count} items, stopping pagination")
                break
            
            page += 1
        
        logger.info(f"Fetched total of {len(all_results)} items from {endpoint}")
        return all_results
    
    def put(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """Make a PUT request to the API."""
        url = f"{self.base_url}/api/{endpoint}"
        try:
            response = self.session.put(
                url, 
                headers=self.headers, 
                json=data,
                verify=self.verify
            )
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"PUT {endpoint} failed: {response.status_code} - {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"PUT request error: {e}")
            return None
    
    def patch(self, endpoint: str, data: Dict) -> Optional[Dict]:
        """Make a PATCH request to the API."""
        url = f"{self.base_url}/api/{endpoint}"
        try:
            response = self.session.patch(
                url, 
                headers=self.headers, 
                json=data,
                verify=self.verify
            )
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"PATCH {endpoint} failed: {response.status_code} - {response.text}")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"PATCH request error: {e}")
            return None
    
    def logout(self):
        """Logout from the controller."""
        logout_url = f"{self.base_url}/logout"
        try:
            self.session.post(logout_url, headers=self.headers, verify=self.verify)
            logger.info("Logged out from controller")
        except requests.exceptions.RequestException:
            pass


def extract_uuid_from_ref(ref: str) -> str:
    """Extract UUID from an API reference URL."""
    if ref:
        # Handle both formats: /api/applicationprofile/uuid and /api/applicationprofile?name=xyz
        if "?" in ref:
            return ref.split("?")[0].split("/")[-1]
        return ref.split("/")[-1]
    return ""


def markers_to_dict(markers: List[Dict]) -> Dict[str, List[str]]:
    """Convert markers list to a dictionary for easy comparison."""
    result = {}
    for marker in markers:
        key = marker.get("key", "")
        values = marker.get("values", [])
        result[key] = sorted(values) if values else []
    return result


def dict_to_markers(markers_dict: Dict[str, List[str]]) -> List[Dict]:
    """Convert dictionary back to markers list format."""
    result = []
    for key, values in markers_dict.items():
        marker = {"key": key}
        if values:
            marker["values"] = values
        result.append(marker)
    return result


def merge_markers(existing_markers: List[Dict], new_markers: List[Dict]) -> List[Dict]:
    """
    Merge markers, handling the case where same key may have multiple values.
    New values are added to existing values for the same key.
    """
    existing_dict = markers_to_dict(existing_markers)
    new_dict = markers_to_dict(new_markers)
    
    # Merge new markers into existing
    for key, values in new_dict.items():
        if key in existing_dict:
            # Combine values and remove duplicates
            combined = list(set(existing_dict[key] + values))
            existing_dict[key] = sorted(combined)
        else:
            existing_dict[key] = values
    
    return dict_to_markers(existing_dict)


def markers_need_update(existing_markers: List[Dict], vs_markers: List[Dict]) -> bool:
    """
    Check if ApplicationProfile markers need to be updated to include VS markers.
    Returns True if VS has markers that are not fully present in ApplicationProfile.
    """
    existing_dict = markers_to_dict(existing_markers)
    vs_dict = markers_to_dict(vs_markers)
    
    for key, vs_values in vs_dict.items():
        if key not in existing_dict:
            return True
        # Check if all VS values are in existing values
        for val in vs_values:
            if val not in existing_dict[key]:
                return True
    return False


def role_filter_matches_markers(role_filter: Dict, markers: List[Dict]) -> bool:
    """
    Check if a role's filter matches the given markers.
    
    A role can access an object if:
    - The role has allow_unlabelled_access=True and object has no markers, OR
    - The role's filter matches at least one of the object's markers
    
    Filter match logic:
    - ROLE_FILTER_EQUALS: filter.key == marker.key AND filter.values intersects marker.values
    - If filter has no values (empty), it matches any value for that key (key = *)
    """
    filter_key = role_filter.get("match_label", {}).get("key", "")
    filter_values = role_filter.get("match_label", {}).get("values", [])
    match_operation = role_filter.get("match_operation", "ROLE_FILTER_EQUALS")
    
    markers_dict = markers_to_dict(markers)
    
    if filter_key not in markers_dict:
        return False
    
    marker_values = markers_dict[filter_key]
    
    # If filter has no values, it matches any value for that key
    if not filter_values:
        return True
    
    # Check if any filter value matches any marker value
    if match_operation == "ROLE_FILTER_EQUALS":
        return bool(set(filter_values) & set(marker_values))
    
    # For other match operations (GLOB, etc.), do simple intersection for now
    return bool(set(filter_values) & set(marker_values))


def check_role_access(role: Dict, markers: List[Dict]) -> bool:
    """
    Check if a role can access an object with the given markers.
    
    Returns True if the role can access the object.
    """
    allow_unlabelled = role.get("allow_unlabelled_access", True)
    filters = role.get("filters", [])
    
    # If object has no markers
    if not markers:
        return allow_unlabelled
    
    # If role has no filters
    if not filters:
        return allow_unlabelled
    
    # Check if any filter matches the markers
    for role_filter in filters:
        if role_filter_matches_markers(role_filter, markers):
            return True
    
    # If allow_unlabelled_access is True and no filter matched, 
    # the role can still access (filters are additive, not restrictive when allow_unlabelled=True)
    return allow_unlabelled


def get_roles_with_resource_access(session: AviSession, permission_resource: str = "PERMISSION_APPLICATIONPROFILE") -> List[Dict]:
    """
    Fetch all roles that have at least READ access to the specified resource.
    
    Args:
        session: Authenticated AviSession
        permission_resource: The permission resource to check (e.g., PERMISSION_APPLICATIONPROFILE, PERMISSION_HTTPPOLICYSET)
    """
    roles = session.get_all_pages("role")
    if not roles:
        logger.error("Failed to fetch roles")
        return []
    
    roles_with_access = []
    
    for role in roles:
        privileges = role.get("privileges", [])
        for priv in privileges:
            resource = priv.get("resource", "")
            access_type = priv.get("type", "NO_ACCESS")
            
            # Check if role has access to the specified resource
            if resource == permission_resource and access_type != "NO_ACCESS":
                roles_with_access.append(role)
                break
    
    return roles_with_access


def analyze_rbac_impact(session: AviSession, object_name: str, 
                        current_markers: List[Dict], new_markers: List[Dict],
                        permission_resource: str = "PERMISSION_APPLICATIONPROFILE") -> Dict[str, Any]:
    """
    Analyze which roles would lose access to the object after marker update.
    
    Args:
        session: Authenticated AviSession
        object_name: Name of the object being updated (for logging)
        current_markers: Current markers on the object
        new_markers: New markers that will be set on the object
        permission_resource: The permission resource to check (e.g., PERMISSION_APPLICATIONPROFILE, PERMISSION_HTTPPOLICYSET)
    
    Returns a dict with:
    - roles_losing_access: List of role names that would lose access
    - roles_keeping_access: List of role names that would keep access
    - details: Detailed information about each role
    """
    result = {
        "roles_losing_access": [],
        "roles_keeping_access": [],
        "roles_unchanged": [],
        "details": []
    }
    
    roles = get_roles_with_resource_access(session, permission_resource)
    
    for role in roles:
        role_name = role.get("name", "Unknown")
        allow_unlabelled = role.get("allow_unlabelled_access", True)
        filters = role.get("filters", [])
        
        # Check access with current markers
        can_access_current = check_role_access(role, current_markers)
        
        # Check access with new markers
        can_access_new = check_role_access(role, new_markers)
        
        detail = {
            "role_name": role_name,
            "allow_unlabelled_access": allow_unlabelled,
            "has_filters": len(filters) > 0,
            "filters": [f.get("match_label", {}) for f in filters] if filters else [],
            "can_access_before": can_access_current,
            "can_access_after": can_access_new
        }
        
        if can_access_current and not can_access_new:
            result["roles_losing_access"].append(role_name)
            detail["impact"] = "WILL_LOSE_ACCESS"
        elif not can_access_current and can_access_new:
            result["roles_keeping_access"].append(role_name)
            detail["impact"] = "WILL_GAIN_ACCESS"
        elif can_access_current and can_access_new:
            result["roles_keeping_access"].append(role_name)
            detail["impact"] = "NO_CHANGE"
        else:
            result["roles_unchanged"].append(role_name)
            detail["impact"] = "NO_ACCESS_BEFORE_OR_AFTER"
        
        result["details"].append(detail)
    
    return result


def process_virtualservices(session: AviSession, dry_run: bool = False, 
                            vs_name: Optional[str] = None, vs_uuid: Optional[str] = None,
                            check_rbac: bool = False) -> Dict[str, Any]:
    """
    Process VirtualServices and sync markers to ApplicationProfiles.
    
    Args:
        session: Authenticated AviSession
        dry_run: If True, don't make any changes
        vs_name: Optional - process only this VS by name
        vs_uuid: Optional - process only this VS by UUID
        check_rbac: If True, analyze which roles would lose access after marker update
    
    Returns a summary of the operations performed.
    """
    summary = {
        "total_vs": 0,
        "vs_with_markers": 0,
        "app_profiles_updated": 0,
        "app_profiles_already_synced": 0,
        "errors": 0,
        "rbac_warnings": 0,
        "details": []
    }
    
    # Get VirtualService(s)
    if vs_uuid:
        # Fetch single VS by UUID
        logger.info(f"Fetching VirtualService by UUID: {vs_uuid}")
        vs_response = session.get(f"virtualservice/{vs_uuid}")
        if not vs_response:
            logger.error(f"Failed to fetch VirtualService with UUID: {vs_uuid}")
            return summary
        virtualservices = [vs_response]
    elif vs_name:
        # Fetch single VS by name
        logger.info(f"Fetching VirtualService by name: {vs_name}")
        vs_response = session.get("virtualservice", params={"name": vs_name})
        if not vs_response:
            logger.error(f"Failed to fetch VirtualService with name: {vs_name}")
            return summary
        virtualservices = vs_response.get("results", [])
        if not virtualservices:
            logger.error(f"No VirtualService found with name: {vs_name}")
            return summary
    else:
        # Fetch all VirtualServices with pagination
        logger.info("Fetching all VirtualServices...")
        virtualservices = session.get_all_pages("virtualservice")
        if not virtualservices:
            logger.error("Failed to fetch VirtualServices")
            return summary
    
    summary["total_vs"] = len(virtualservices)
    logger.info(f"Found {len(virtualservices)} VirtualService(s)")
    
    # Cache for ApplicationProfiles to avoid redundant updates
    app_profile_cache = {}
    
    for vs in virtualservices:
        vs_name = vs.get("name", "Unknown")
        vs_uuid = vs.get("uuid", "")
        vs_markers = vs.get("markers", [])
        app_profile_ref = vs.get("application_profile_ref", "")
        
        detail = {
            "vs_name": vs_name,
            "vs_uuid": vs_uuid,
            "vs_markers": vs_markers,
            "app_profile_ref": app_profile_ref,
            "action": None,
            "status": None
        }
        
        if not vs_markers:
            detail["action"] = "skipped"
            detail["status"] = "No markers on VS"
            logger.debug(f"VS '{vs_name}': No markers present, skipping")
            summary["details"].append(detail)
            continue
        
        summary["vs_with_markers"] += 1
        logger.info(f"VS '{vs_name}': Found markers: {json.dumps(vs_markers)}")
        
        if not app_profile_ref:
            detail["action"] = "skipped"
            detail["status"] = "No ApplicationProfile associated"
            logger.warning(f"VS '{vs_name}': No ApplicationProfile reference")
            summary["details"].append(detail)
            continue
        
        # Extract ApplicationProfile UUID
        app_profile_uuid = extract_uuid_from_ref(app_profile_ref)
        
        # Check cache first
        if app_profile_uuid in app_profile_cache:
            app_profile = app_profile_cache[app_profile_uuid]
        else:
            # Fetch ApplicationProfile
            app_profile = session.get(f"applicationprofile/{app_profile_uuid}")
            if not app_profile:
                detail["action"] = "error"
                detail["status"] = "Failed to fetch ApplicationProfile"
                logger.error(f"VS '{vs_name}': Failed to fetch ApplicationProfile {app_profile_uuid}")
                summary["errors"] += 1
                summary["details"].append(detail)
                continue
            app_profile_cache[app_profile_uuid] = app_profile
        
        app_profile_name = app_profile.get("name", "Unknown")
        app_profile_type = app_profile.get("type", "")
        app_profile_markers = app_profile.get("markers", [])
        
        # Skip DNS-type ApplicationProfiles to avoid WEBERR_CHECK_DNSVS_PROFILE_CHANGE_NOT_ALLOWED error
        # This error occurs when updating ApplicationProfiles attached to DNS VirtualServices 
        # that are configured in SystemConfiguration.dns_virtualservice_uuids
        if app_profile_type == "APPLICATION_PROFILE_TYPE_DNS":
            detail["action"] = "skipped"
            detail["status"] = "Skipped DNS-type ApplicationProfile (cannot update due to SystemConfiguration constraint)"
            logger.warning(f"  ApplicationProfile '{app_profile_name}': Skipping - DNS type profiles cannot be updated when attached to system DNS VS")
            summary["details"].append(detail)
            continue
        
        logger.info(f"  ApplicationProfile '{app_profile_name}': Current markers: {json.dumps(app_profile_markers)}")
        
        # Check if update is needed
        if not markers_need_update(app_profile_markers, vs_markers):
            detail["action"] = "skipped"
            detail["status"] = "Markers already synced"
            logger.info(f"  ApplicationProfile '{app_profile_name}': Markers already contain VS markers")
            summary["app_profiles_already_synced"] += 1
            summary["details"].append(detail)
            continue
        
        # Merge markers
        merged_markers = merge_markers(app_profile_markers, vs_markers)
        logger.info(f"  ApplicationProfile '{app_profile_name}': Merged markers: {json.dumps(merged_markers)}")
        
        # RBAC Impact Analysis
        if check_rbac:
            logger.info(f"  Analyzing RBAC impact for ApplicationProfile '{app_profile_name}'...")
            rbac_impact = analyze_rbac_impact(session, app_profile_name, app_profile_markers, merged_markers)
            detail["rbac_impact"] = rbac_impact
            
            if rbac_impact["roles_losing_access"]:
                summary["rbac_warnings"] += 1
                logger.warning(f"  ⚠️  RBAC WARNING: The following roles will LOSE access to ApplicationProfile '{app_profile_name}':")
                for role_name in rbac_impact["roles_losing_access"]:
                    logger.warning(f"      - {role_name}")
                
                # Find details for roles losing access
                for role_detail in rbac_impact["details"]:
                    if role_detail["impact"] == "WILL_LOSE_ACCESS":
                        logger.warning(f"        Role '{role_detail['role_name']}': "
                                       f"allow_unlabelled_access={role_detail['allow_unlabelled_access']}, "
                                       f"filters={json.dumps(role_detail['filters'])}")
            else:
                logger.info(f"  ✓ RBAC OK: No roles will lose access to ApplicationProfile '{app_profile_name}'")
            
            # In dry run with RBAC check, show impact but don't update
            if dry_run:
                detail["action"] = "would_update"
                detail["status"] = f"Would update markers to: {json.dumps(merged_markers)}"
                if rbac_impact["roles_losing_access"]:
                    detail["status"] += f" (WARNING: {len(rbac_impact['roles_losing_access'])} role(s) would lose access)"
                logger.info(f"  [DRY RUN] Would update ApplicationProfile '{app_profile_name}'")
                summary["details"].append(detail)
                continue
        elif dry_run:
            detail["action"] = "would_update"
            detail["status"] = f"Would update markers to: {json.dumps(merged_markers)}"
            logger.info(f"  [DRY RUN] Would update ApplicationProfile '{app_profile_name}'")
            summary["details"].append(detail)
            continue
        
        # Update ApplicationProfile using PATCH
        patch_data = {
            "replace": {
                "markers": merged_markers
            }
        }
        
        result = session.patch(f"applicationprofile/{app_profile_uuid}", patch_data)
        
        if result:
            detail["action"] = "updated"
            detail["status"] = f"Updated markers to: {json.dumps(merged_markers)}"
            logger.info(f"  Successfully updated ApplicationProfile '{app_profile_name}'")
            summary["app_profiles_updated"] += 1
            # Update cache
            app_profile_cache[app_profile_uuid]["markers"] = merged_markers
        else:
            detail["action"] = "error"
            detail["status"] = "Failed to update ApplicationProfile"
            logger.error(f"  Failed to update ApplicationProfile '{app_profile_name}'")
            summary["errors"] += 1
        
        summary["details"].append(detail)
    
    return summary


def process_http_policies(session: AviSession, dry_run: bool = False, 
                          vs_name: Optional[str] = None, vs_uuid: Optional[str] = None,
                          check_rbac: bool = False) -> Dict[str, Any]:
    """
    Process VirtualServices and sync markers to associated HTTPPolicySets.
    
    Args:
        session: Authenticated AviSession
        dry_run: If True, don't make any changes
        vs_name: Optional - process only this VS by name
        vs_uuid: Optional - process only this VS by UUID
        check_rbac: If True, analyze which roles would lose access after marker update
    
    Returns a summary of the operations performed.
    """
    summary = {
        "total_vs": 0,
        "vs_with_markers": 0,
        "http_policies_updated": 0,
        "http_policies_already_synced": 0,
        "errors": 0,
        "rbac_warnings": 0,
        "details": []
    }
    
    # Get VirtualService(s)
    if vs_uuid:
        logger.info(f"Fetching VirtualService by UUID: {vs_uuid}")
        vs_response = session.get(f"virtualservice/{vs_uuid}")
        if not vs_response:
            logger.error(f"Failed to fetch VirtualService with UUID: {vs_uuid}")
            return summary
        virtualservices = [vs_response]
    elif vs_name:
        logger.info(f"Fetching VirtualService by name: {vs_name}")
        vs_response = session.get("virtualservice", params={"name": vs_name})
        if not vs_response:
            logger.error(f"Failed to fetch VirtualService with name: {vs_name}")
            return summary
        virtualservices = vs_response.get("results", [])
        if not virtualservices:
            logger.error(f"No VirtualService found with name: {vs_name}")
            return summary
    else:
        # Fetch all VirtualServices with pagination
        logger.info("Fetching all VirtualServices...")
        virtualservices = session.get_all_pages("virtualservice")
        if not virtualservices:
            logger.error("Failed to fetch VirtualServices")
            return summary
    
    summary["total_vs"] = len(virtualservices)
    logger.info(f"Found {len(virtualservices)} VirtualService(s)")
    
    # Cache for HTTPPolicySets to avoid redundant updates
    http_policy_cache = {}
    
    for vs in virtualservices:
        vs_name_local = vs.get("name", "Unknown")
        vs_uuid_local = vs.get("uuid", "")
        vs_markers = vs.get("markers", [])
        http_policies = vs.get("http_policies", [])
        
        if not vs_markers:
            logger.debug(f"VS '{vs_name_local}': No markers present, skipping")
            continue
        
        summary["vs_with_markers"] += 1
        logger.info(f"VS '{vs_name_local}': Found markers: {json.dumps(vs_markers)}")
        
        if not http_policies:
            logger.info(f"VS '{vs_name_local}': No HTTP policies associated")
            continue
        
        logger.info(f"VS '{vs_name_local}': Found {len(http_policies)} HTTP policy reference(s)")
        
        for http_policy_entry in http_policies:
            http_policy_ref = http_policy_entry.get("http_policy_set_ref", "")
            if not http_policy_ref:
                # Try uuid field directly
                http_policy_ref = http_policy_entry.get("http_policy_set_uuid", "")
            
            if not http_policy_ref:
                logger.warning(f"VS '{vs_name_local}': HTTP policy entry has no reference")
                continue
            
            # Extract HTTPPolicySet UUID
            http_policy_uuid = extract_uuid_from_ref(http_policy_ref)
            
            detail = {
                "vs_name": vs_name_local,
                "vs_uuid": vs_uuid_local,
                "vs_markers": vs_markers,
                "http_policy_uuid": http_policy_uuid,
                "action": None,
                "status": None
            }
            
            # Check cache first
            if http_policy_uuid in http_policy_cache:
                http_policy = http_policy_cache[http_policy_uuid]
            else:
                # Fetch HTTPPolicySet
                http_policy = session.get(f"httppolicyset/{http_policy_uuid}")
                if not http_policy:
                    detail["action"] = "error"
                    detail["status"] = "Failed to fetch HTTPPolicySet"
                    logger.error(f"VS '{vs_name_local}': Failed to fetch HTTPPolicySet {http_policy_uuid}")
                    summary["errors"] += 1
                    summary["details"].append(detail)
                    continue
                http_policy_cache[http_policy_uuid] = http_policy
            
            http_policy_name = http_policy.get("name", "Unknown")
            http_policy_markers = http_policy.get("markers", [])
            
            logger.info(f"  HTTPPolicySet '{http_policy_name}': Current markers: {json.dumps(http_policy_markers)}")
            
            # Check if update is needed
            if not markers_need_update(http_policy_markers, vs_markers):
                detail["action"] = "skipped"
                detail["status"] = "Markers already synced"
                logger.info(f"  HTTPPolicySet '{http_policy_name}': Markers already contain VS markers")
                summary["http_policies_already_synced"] += 1
                summary["details"].append(detail)
                continue
            
            # Merge markers
            merged_markers = merge_markers(http_policy_markers, vs_markers)
            logger.info(f"  HTTPPolicySet '{http_policy_name}': Merged markers: {json.dumps(merged_markers)}")
            
            # RBAC Impact Analysis
            if check_rbac:
                logger.info(f"  Analyzing RBAC impact for HTTPPolicySet '{http_policy_name}'...")
                rbac_impact = analyze_rbac_impact(session, http_policy_name, http_policy_markers, merged_markers, 
                                                   permission_resource="PERMISSION_HTTPPOLICYSET")
                detail["rbac_impact"] = rbac_impact
                
                if rbac_impact["roles_losing_access"]:
                    summary["rbac_warnings"] += 1
                    logger.warning(f"  ⚠️  RBAC WARNING: The following roles will LOSE access to HTTPPolicySet '{http_policy_name}':")
                    for role_name in rbac_impact["roles_losing_access"]:
                        logger.warning(f"      - {role_name}")
                else:
                    logger.info(f"  ✓ RBAC OK: No roles will lose access to HTTPPolicySet '{http_policy_name}'")
                
                if dry_run:
                    detail["action"] = "would_update"
                    detail["status"] = f"Would update markers to: {json.dumps(merged_markers)}"
                    if rbac_impact["roles_losing_access"]:
                        detail["status"] += f" (WARNING: {len(rbac_impact['roles_losing_access'])} role(s) would lose access)"
                    logger.info(f"  [DRY RUN] Would update HTTPPolicySet '{http_policy_name}'")
                    summary["details"].append(detail)
                    continue
            elif dry_run:
                detail["action"] = "would_update"
                detail["status"] = f"Would update markers to: {json.dumps(merged_markers)}"
                logger.info(f"  [DRY RUN] Would update HTTPPolicySet '{http_policy_name}'")
                summary["details"].append(detail)
                continue
            
            # Update HTTPPolicySet using PATCH
            patch_data = {
                "replace": {
                    "markers": merged_markers
                }
            }
            
            result = session.patch(f"httppolicyset/{http_policy_uuid}", patch_data)
            
            if result:
                detail["action"] = "updated"
                detail["status"] = f"Updated markers to: {json.dumps(merged_markers)}"
                logger.info(f"  Successfully updated HTTPPolicySet '{http_policy_name}'")
                summary["http_policies_updated"] += 1
                # Update cache
                http_policy_cache[http_policy_uuid]["markers"] = merged_markers
            else:
                detail["action"] = "error"
                detail["status"] = "Failed to update HTTPPolicySet"
                logger.error(f"  Failed to update HTTPPolicySet '{http_policy_name}'")
                summary["errors"] += 1
            
            summary["details"].append(detail)
    
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Sync markers from VirtualServices to ApplicationProfiles and/or HTTPPolicySets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sync markers to ApplicationProfiles (default behavior)
  python marker_sync_tool.py --controller 10.10.10.10 --username admin --password admin123
  
  # Sync markers to HTTPPolicySets only
  python marker_sync_tool.py --controller 10.10.10.10 --username admin --password admin123 --sync-http-policies
  
  # Sync markers to BOTH ApplicationProfiles and HTTPPolicySets
  python marker_sync_tool.py --controller 10.10.10.10 --username admin --password admin123 --sync-app-profiles --sync-http-policies
  
  # Dry run (no changes made)
  python marker_sync_tool.py --controller 10.10.10.10 --username admin --password admin123 --dry-run
  
  # Sync for a SINGLE VirtualService by name
  python marker_sync_tool.py --controller 10.10.10.10 --username admin --password admin123 --vs-name my-virtualservice
  
  # Sync HTTPPolicySets for a single VS
  python marker_sync_tool.py --controller 10.10.10.10 --username admin --password admin123 --vs-name my-vs --sync-http-policies
  
  # Check RBAC impact before updating
  python marker_sync_tool.py --controller 10.10.10.10 --username admin --password admin123 --check-rbac --dry-run
  
  # Check RBAC impact for HTTPPolicySets
  python marker_sync_tool.py --controller 10.10.10.10 --username admin --password admin123 --sync-http-policies --check-rbac --dry-run
        """
    )
    
    parser.add_argument("--controller", "-c", required=True, help="Controller IP or hostname")
    parser.add_argument("--username", "-u", required=True, help="Username")
    parser.add_argument("--password", "-p", required=True, help="Password")
    parser.add_argument("--tenant", "-t", default="admin", help="Tenant name (default: admin)")
    parser.add_argument("--api-version", default="30.2.1", help="API version (default: 30.2.1)")
    parser.add_argument("--vs-name", help="Process only this VirtualService (by name)")
    parser.add_argument("--vs-uuid", help="Process only this VirtualService (by UUID)")
    parser.add_argument("--sync-app-profiles", action="store_true", 
                        help="Sync markers to ApplicationProfiles (default if no sync option specified)")
    parser.add_argument("--sync-http-policies", action="store_true", 
                        help="Sync markers to HTTPPolicySets")
    parser.add_argument("--check-rbac", action="store_true", 
                        help="Analyze RBAC impact - show which roles would lose access to ApplicationProfile after marker update")
    parser.add_argument("--dry-run", "-d", action="store_true", help="Dry run mode - no changes made")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Determine which sync operations to perform
    # If neither is specified, default to ApplicationProfiles
    sync_app_profiles = args.sync_app_profiles
    sync_http_policies = args.sync_http_policies
    if not sync_app_profiles and not sync_http_policies:
        sync_app_profiles = True  # Default behavior
    
    logger.info("=" * 60)
    logger.info("Marker Sync Tool Started")
    logger.info(f"Controller: {args.controller}")
    logger.info(f"Tenant: {args.tenant}")
    if args.vs_name:
        logger.info(f"Target VS (by name): {args.vs_name}")
    elif args.vs_uuid:
        logger.info(f"Target VS (by UUID): {args.vs_uuid}")
    else:
        logger.info("Target: ALL VirtualServices")
    logger.info(f"Sync ApplicationProfiles: {sync_app_profiles}")
    logger.info(f"Sync HTTPPolicySets: {sync_http_policies}")
    logger.info(f"Check RBAC: {args.check_rbac}")
    logger.info(f"Dry Run: {args.dry_run}")
    logger.info(f"Log File: {LOG_FILE}")
    logger.info("=" * 60)
    
    # Create session and login
    session = AviSession(
        controller=args.controller,
        username=args.username,
        password=args.password,
        tenant=args.tenant,
        api_version=args.api_version
    )
    
    if not session.login():
        logger.error("Failed to login to controller. Exiting.")
        sys.exit(1)
    
    all_summaries = {}
    
    try:
        # Process ApplicationProfiles
        if sync_app_profiles:
            logger.info("")
            logger.info("=" * 60)
            logger.info("SYNCING MARKERS TO APPLICATION PROFILES")
            logger.info("=" * 60)
            
            app_profile_summary = process_virtualservices(
                session, 
                dry_run=args.dry_run,
                vs_name=args.vs_name,
                vs_uuid=args.vs_uuid,
                check_rbac=args.check_rbac
            )
            all_summaries["application_profiles"] = app_profile_summary
            
            # Print ApplicationProfile summary
            logger.info("")
            logger.info("APPLICATION PROFILE SUMMARY")
            logger.info("-" * 40)
            logger.info(f"Total VirtualServices: {app_profile_summary['total_vs']}")
            logger.info(f"VirtualServices with markers: {app_profile_summary['vs_with_markers']}")
            logger.info(f"ApplicationProfiles updated: {app_profile_summary['app_profiles_updated']}")
            logger.info(f"ApplicationProfiles already synced: {app_profile_summary['app_profiles_already_synced']}")
            if args.check_rbac:
                logger.info(f"RBAC Warnings: {app_profile_summary['rbac_warnings']}")
            logger.info(f"Errors: {app_profile_summary['errors']}")
            
            if args.check_rbac and app_profile_summary['rbac_warnings'] > 0:
                logger.warning("")
                logger.warning("⚠️  RBAC IMPACT DETECTED for ApplicationProfiles!")
                logger.warning("Some roles will lose access after marker update.")
        
        # Process HTTPPolicySets
        if sync_http_policies:
            logger.info("")
            logger.info("=" * 60)
            logger.info("SYNCING MARKERS TO HTTP POLICY SETS")
            logger.info("=" * 60)
            
            http_policy_summary = process_http_policies(
                session, 
                dry_run=args.dry_run,
                vs_name=args.vs_name,
                vs_uuid=args.vs_uuid,
                check_rbac=args.check_rbac
            )
            all_summaries["http_policy_sets"] = http_policy_summary
            
            # Print HTTPPolicySet summary
            logger.info("")
            logger.info("HTTP POLICY SET SUMMARY")
            logger.info("-" * 40)
            logger.info(f"Total VirtualServices: {http_policy_summary['total_vs']}")
            logger.info(f"VirtualServices with markers: {http_policy_summary['vs_with_markers']}")
            logger.info(f"HTTPPolicySets updated: {http_policy_summary['http_policies_updated']}")
            logger.info(f"HTTPPolicySets already synced: {http_policy_summary['http_policies_already_synced']}")
            if args.check_rbac:
                logger.info(f"RBAC Warnings: {http_policy_summary['rbac_warnings']}")
            logger.info(f"Errors: {http_policy_summary['errors']}")
            
            if args.check_rbac and http_policy_summary['rbac_warnings'] > 0:
                logger.warning("")
                logger.warning("⚠️  RBAC IMPACT DETECTED for HTTPPolicySets!")
                logger.warning("Some roles will lose access after marker update.")
        
        # Final summary
        logger.info("")
        logger.info("=" * 60)
        logger.info("OVERALL SUMMARY")
        logger.info("=" * 60)
        
        total_updated = 0
        total_errors = 0
        total_rbac_warnings = 0
        
        if sync_app_profiles:
            total_updated += app_profile_summary['app_profiles_updated']
            total_errors += app_profile_summary['errors']
            total_rbac_warnings += app_profile_summary.get('rbac_warnings', 0)
        
        if sync_http_policies:
            total_updated += http_policy_summary['http_policies_updated']
            total_errors += http_policy_summary['errors']
            total_rbac_warnings += http_policy_summary.get('rbac_warnings', 0)
        
        logger.info(f"Total objects updated: {total_updated}")
        logger.info(f"Total errors: {total_errors}")
        if args.check_rbac:
            logger.info(f"Total RBAC warnings: {total_rbac_warnings}")
        logger.info("=" * 60)
        
        # Write detailed report
        report_file = f"marker_sync_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(all_summaries, f, indent=2)
        logger.info(f"Detailed report saved to: {report_file}")
        
    finally:
        session.logout()
    
    logger.info("Marker Sync Tool Completed")


if __name__ == "__main__":
    main()

