"""Demo Protected Resource — requires Gateway authorization tokens.

A simple FastAPI app with CRUD endpoints for customers.
Each endpoint uses the Gateway middleware to verify that the caller
holds a valid, scoped, non-expired Ed25519-signed token.

Usage:
    GATEWAY_URL=http://localhost:8080 uvicorn examples.protected_resource.main:app --port 8081
"""

from __future__ import annotations

import logging
import os
import uuid

from fastapi import Depends, FastAPI

# Add project root to path for gateway imports
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from gateway.middleware import require_gateway_token

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("protected_resource")

app = FastAPI(
    title="Protected Resource (Demo)",
    description="Customer API protected by Agent Authorization Gateway tokens",
)

# In-memory customer store
CUSTOMERS = {
    "c1": {"id": "c1", "name": "Alice Corp", "email": "alice@corp.com", "plan": "enterprise"},
    "c2": {"id": "c2", "name": "Bob LLC", "email": "bob@llc.com", "plan": "startup"},
    "c3": {"id": "c3", "name": "Charlie Inc", "email": "charlie@inc.com", "plan": "free"},
}


@app.get("/customers/{customer_id}")
async def read_customer(
    customer_id: str,
    claims: dict = Depends(require_gateway_token("read", "staging-database")),
):
    """Read a customer by ID. Requires a Gateway token with action=read, resource=staging-database."""
    logger.info(f"READ customer={customer_id} by agent={claims.get('sub')} token_jti={claims.get('jti','?')[:8]}")
    customer = CUSTOMERS.get(customer_id)
    if not customer:
        return {"error": "not_found", "customer_id": customer_id}
    return {"customer": customer, "authorized_by": claims.get("sub"), "receipt": claims.get("receipt_hash")}


@app.post("/customers")
async def create_customer(
    name: str = "New Customer",
    email: str = "new@customer.com",
    claims: dict = Depends(require_gateway_token("query", "staging-database")),
):
    """Create a new customer. Requires a Gateway token with action=query, resource=staging-database."""
    cid = f"c{len(CUSTOMERS) + 1}"
    CUSTOMERS[cid] = {"id": cid, "name": name, "email": email, "plan": "free"}
    logger.info(f"CREATE customer={cid} by agent={claims.get('sub')} token_jti={claims.get('jti','?')[:8]}")
    return {"customer": CUSTOMERS[cid], "authorized_by": claims.get("sub")}


@app.delete("/customers/{customer_id}")
async def delete_customer(
    customer_id: str,
    claims: dict = Depends(require_gateway_token("delete", "staging-database")),
):
    """Delete a customer. Requires a Gateway token with action=delete, resource=staging-database."""
    logger.info(f"DELETE customer={customer_id} by agent={claims.get('sub')} token_jti={claims.get('jti','?')[:8]}")
    if customer_id in CUSTOMERS:
        deleted = CUSTOMERS.pop(customer_id)
        return {"deleted": deleted, "authorized_by": claims.get("sub")}
    return {"error": "not_found", "customer_id": customer_id}


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "protected-resource", "customers": len(CUSTOMERS)}
