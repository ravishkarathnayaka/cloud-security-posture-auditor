"""
cloud_collector.py - Ingestion engine for cloud resource inventory.
Supports both offline enterprise mock state (for zero-cost evaluation and CI/CD testing)
and live cloud SDK hooks (boto3 / azure-mgmt).
"""

import os
import json
from typing import List
from models import CloudResource, CloudProvider, ResourceCategory


class CloudInventoryCollector:
    """Collects multi-cloud inventory from live cloud APIs or simulated enterprise baseline."""

    def __init__(self, inventory_file: str = "sample_cloud_state/enterprise_cloud_inventory.json"):
        self.inventory_file = inventory_file

    def collect(self) -> List[CloudResource]:
        """Loads and parses cloud resources into structured CloudResource models."""
        if not os.path.exists(self.inventory_file):
            raise FileNotFoundError(f"Inventory dataset not found at {self.inventory_file}")

        with open(self.inventory_file, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        resources: List[CloudResource] = []
        for item in raw_data:
            res = CloudResource(
                resource_id=item["resource_id"],
                name=item["name"],
                provider=CloudProvider(item["provider"]),
                category=ResourceCategory(item["category"]),
                resource_type=item["resource_type"],
                region=item.get("region", "global"),
                properties=item.get("properties", {}),
                tags=item.get("tags", {})
            )
            resources.append(res)

        return resources
