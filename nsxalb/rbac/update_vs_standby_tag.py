#!/usr/bin/env python3
# Copyright 2024 Broadcom. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""
Update VirtualService Active Standby SE Tag

This script updates the active_standby_se_tag on VirtualServices from
ACTIVE_STANDBY_SE_2 to ACTIVE_STANDBY_SE_1 using the Avi SDK with pagination.

Usage:
    python update_vs_standby_tag.py --controller <ip> --username <user> --password <pass>
    python update_vs_standby_tag.py --controller <ip> --username <user> --password <pass> --dry-run
"""

import argparse
import logging
import sys

try:
    from avi.sdk.avi_api import ApiSession
except ImportError:
    print("ERROR: avi.sdk not found. Please install the Avi SDK:")
    print("  pip install avisdk")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def update_vs_standby_tag(
    controller: str,
    username: str,
    password: str,
    tenant: str = "admin",
    from_tag: str = "ACTIVE_STANDBY_SE_2",
    to_tag: str = "ACTIVE_STANDBY_SE_1",
    dry_run: bool = False
):
    """
    Update active_standby_se_tag on all VirtualServices.
    Uses pagination to handle large numbers of VS.
    """
    
    # Initialize session
    logger.info(f"Connecting to controller {controller}...")
    try:
        api = ApiSession.get_session(controller, username, password, tenant=tenant)
        logger.info("Successfully connected to controller")
    except Exception as e:
        logger.error(f"Failed to connect to controller: {e}")
        sys.exit(1)
    
    count = 0
    updated_count = 0
    skipped_count = 0
    error_count = 0
    
    logger.info("")
    logger.info("=" * 80)
    logger.info(f"Updating VS active_standby_se_tag: {from_tag} -> {to_tag}")
    logger.info("=" * 80)
    
    if dry_run:
        logger.info("[DRY RUN MODE - No changes will be made]")
        logger.info("")
    
    # Start with the first page
    path = "virtualservice"
    page_num = 1
    
    while path:
        logger.info(f"Fetching page {page_num}...")
        
        try:
            resp = api.get(path)
            
            if resp.status_code != 200:
                logger.error(f"Failed to fetch virtualservices: {resp.status_code} - {resp.text}")
                break
            
            response = resp.json()
            results = response.get('results', [])
            
            if not results:
                logger.info(f"No more results on page {page_num}")
                break
            
            logger.info(f"Page {page_num}: Found {len(results)} VirtualServices")
            
            for vs in results:
                count += 1
                vs_name = vs.get('name', 'Unknown')
                vs_uuid = vs.get('uuid', '')
                current_tag = vs.get('active_standby_se_tag', '')
                
                # Check for the specific tag
                if current_tag == from_tag:
                    logger.info(f"[{count}] {vs_name}: tag='{from_tag}' -> Updating to '{to_tag}'...")
                    
                    if dry_run:
                        logger.info(f"    [DRY RUN] Would update {vs_name}")
                        updated_count += 1
                        continue
                    
                    # Perform a PATCH to update the tag
                    patch_data = {'replace': {'active_standby_se_tag': to_tag}}
                    
                    try:
                        patch_resp = api.patch(f"virtualservice/{vs_uuid}", data=patch_data)
                        
                        if patch_resp.status_code == 200:
                            logger.info(f"    ✓ Successfully updated {vs_name}")
                            updated_count += 1
                        else:
                            logger.error(f"    ✗ Failed to update {vs_name}: {patch_resp.status_code} - {patch_resp.text}")
                            error_count += 1
                    except Exception as e:
                        logger.error(f"    ✗ Failed to update {vs_name}: {e}")
                        error_count += 1
                else:
                    logger.debug(f"[{count}] {vs_name}: tag='{current_tag}' (not '{from_tag}'), skipping")
                    skipped_count += 1
            
            # Check if there is a next page link in the metadata
            next_url = response.get('next')
            if next_url:
                # Extract the relative path from the full URL
                path = next_url.split('/api/')[-1]
                page_num += 1
            else:
                path = None
                
        except Exception as e:
            logger.error(f"Error fetching page {page_num}: {e}")
            break
    
    # Print summary
    logger.info("")
    logger.info("=" * 80)
    logger.info("SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Total VirtualServices processed: {count}")
    logger.info(f"VS with tag '{from_tag}': {updated_count + error_count}")
    logger.info(f"VS updated to '{to_tag}': {updated_count}")
    logger.info(f"VS skipped (different tag): {skipped_count}")
    logger.info(f"Errors: {error_count}")
    logger.info("=" * 80)
    
    if dry_run:
        logger.info("")
        logger.info("DRY RUN COMPLETE - No changes were made")
        logger.info("Run without --dry-run to apply changes")
    
    return error_count == 0


def main():
    parser = argparse.ArgumentParser(
        description="Update VirtualService active_standby_se_tag",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Dry run - see what would be changed
  python update_vs_standby_tag.py --controller 10.10.10.10 --username admin --password admin123 --dry-run

  # Execute changes (default: ACTIVE_STANDBY_SE_2 -> ACTIVE_STANDBY_SE_1)
  python update_vs_standby_tag.py --controller 10.10.10.10 --username admin --password admin123

  # Custom tag values
  python update_vs_standby_tag.py --controller 10.10.10.10 --username admin --password admin123 --from-tag ACTIVE_STANDBY_SE_2 --to-tag ACTIVE_STANDBY_SE_1
"""
    )
    
    parser.add_argument("--controller", required=True, help="Controller IP or hostname")
    parser.add_argument("--username", required=True, help="Username")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--tenant", default="admin", help="Tenant (default: admin)")
    parser.add_argument("--from-tag", default="ACTIVE_STANDBY_SE_2",
                        help="Current tag value to match (default: ACTIVE_STANDBY_SE_2)")
    parser.add_argument("--to-tag", default="ACTIVE_STANDBY_SE_1",
                        help="New tag value to set (default: ACTIVE_STANDBY_SE_1)")
    parser.add_argument("--dry-run", action="store_true", help="Preview changes without making them")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose/debug output")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("=" * 80)
    logger.info("Update VirtualService Active Standby SE Tag")
    logger.info("=" * 80)
    logger.info(f"Controller: {args.controller}")
    logger.info(f"Username: {args.username}")
    logger.info(f"Tenant: {args.tenant}")
    logger.info(f"From Tag: {args.from_tag}")
    logger.info(f"To Tag: {args.to_tag}")
    logger.info(f"Dry Run: {args.dry_run}")
    logger.info("=" * 80)
    
    success = update_vs_standby_tag(
        controller=args.controller,
        username=args.username,
        password=args.password,
        tenant=args.tenant,
        from_tag=args.from_tag,
        to_tag=args.to_tag,
        dry_run=args.dry_run
    )
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
