from typing import Any, Dict, List, Optional, Annotated
# from mcp.server.fastmcp import FastMCP
from fastmcp import FastMCP
import os
from pydantic import BaseModel, Field
from dotenv import load_dotenv
# import pyodbc
import pymssql
import time, logging, uuid, json
from datetime import datetime, timedelta
from typing_extensions import Annotated
# import base64, fitz 

# For interacting with Azure Blob storage
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, generate_blob_sas, BlobSasPermissions

load_dotenv() 

logger = logging.getLogger("mcp.tools")


server = os.getenv("SQL_SERVER")
username = os.getenv("SQL_USERNAME")
password = os.getenv("SQL_PASSWORD")
auth_token = os.getenv("MCP_AUTH_TOKEN", "")  
port = int(os.getenv("PORT", "8000"))
driver = 'ODBC Driver 17 for SQL Server'

APPROVED_TABLES: Dict[str, set[str]] = {
    "BI-GoldSQL": "*", # All tables allowed from GOLD
    "BI-ProdSQL": {
        "DWH_ProductImages",
        "DWH_PartEXTFILE",
        "DWH_MotoradParts"
    },
}


# def conn_str_for_db(db_name: str) -> str:
#     return (
#         "DRIVER={ODBC Driver 17 for SQL Server};"
#         f"SERVER={server};DATABASE={db_name};"
#         f"UID={username};PWD={password};"
#         "Encrypt=yes;TrustServerCertificate=no;Connection Timeout=15;"
#     )

def get_connection(db_name: str):
    return pymssql.connect(
        server=server,
        user=username,
        password=password,
        database=db_name,
        timeout=15,
        login_timeout=15
    )


mcp = FastMCP("DustAI")

# ---------------------------------------------------------
# Helper: very small query runner with auditing and timeouts
# ---------------------------------------------------------
# def run_query(db_name: str, sql: str, params: List[Any]) -> List[Dict[str, Any]]:
#     t0 = time.time()
#     with pyodbc.connect(conn_str_for_db(db_name), timeout=15) as conn:
#         cur = conn.cursor()
#         cur.execute(sql, params)
#         cols = [c[0] for c in cur.description]
#         rows = [dict(zip(cols, r)) for r in cur.fetchall()]
#     dur_ms = int((time.time() - t0) * 1000)
#     print(f"[AUDIT] db={db_name} rows={len(rows)} dur_ms={dur_ms} sql={sql[:160]!r} params={params!r}")
#     return rows

def run_query(db_name: str, sql: str, params: List[Any]) -> List[Dict[str, Any]]:
    t0 = time.time()
    conn = get_connection(db_name)
    try:
        cur = conn.cursor(as_dict=True)  # Returns rows as dictionaries
        cur.execute(sql, params)
        rows = cur.fetchall()
    finally:
        conn.close()
    
    dur_ms = int((time.time() - t0) * 1000)
    print(f"[AUDIT] db={db_name} rows={len(rows)} dur_ms={dur_ms} sql={sql[:160]!r} params={params!r}")
    return rows

# Auth check (dev). In prod, prefer mTLS/IP allowlist and/or a gateway.
def auth_check(headers: Dict[str, str]):
    if auth_token and headers.get("authorization") != f"Bearer {auth_token}":
        raise Exception("Unauthorized")
    

# Pydantic schemas for tool inputs
# table_name is just the bare table (no schema/db); we select DB by lookup
# filters are simple equality predicates to keep things predictable
class QueryTableIn(BaseModel):
    table_name: str = Field(..., description="One of the allow-listed table names (no schema).")
    limit: Annotated[int, Field(ge=1, le=200)] = 50
    filters: Optional[Dict[str, Any]] = Field(
        None,
        description="Optional equality filters: { 'ColumnName': value }"
    )

# Quick discovery of allowed tables for the agent
class ListTablesOut(BaseModel):
    databases: Dict[str, List[str]]

# Helper function to list all GOLD tables 
def get_tables_from_database(db_name: str) -> List[str]:
    """Fetch all table names from a database's schema."""
    sql = """
        SELECT TABLE_NAME 
        FROM INFORMATION_SCHEMA.TABLES 
        WHERE TABLE_TYPE = 'BASE TABLE' 
          AND TABLE_SCHEMA = 'dbo'
        ORDER BY TABLE_NAME
    """
    rows = run_query(db_name, sql, [])
    return [row['TABLE_NAME'] for row in rows]

# Tool: list approved tables 
@mcp.tool()
def list_approved_tables() -> dict:
    """List DBs and tables this server allows."""
    result = {}
    
    for db_name, tables in APPROVED_TABLES.items():
        if tables == "*":
            # Wildcard: fetch actual tables from database
            result[db_name] = get_tables_from_database(db_name)
        elif isinstance(tables, set):
            # Explicit list: use what's configured
            result[db_name] = sorted(list(tables))
        else:
            # Fallback for other types
            result[db_name] = []
    
    return {"databases": result}

@mcp.tool()
def query_table(table_name: Annotated[str, Field(description="Approved table name")],
    limit: Annotated[int, Field(ge=1, le=1000, description="Max rows")] = 100,
    filters: Optional[Dict[str, Any]] = None,
) -> dict:

    # Find which DB contains this table
    chosen_db: Optional[str] = None
    for db_name, tables in APPROVED_TABLES.items():
        if tables == "*":
            chosen_db = db_name
            break
        elif isinstance(tables, set) and table_name in tables:
            chosen_db = db_name
            break

    if not chosen_db:
        raise Exception("Table not allowed")

    # For unrestricted DBs, verify table exists to prevent SQL injection
    if APPROVED_TABLES[chosen_db] == "*":
        # Verify table exists in INFORMATION_SCHEMA
        check_sql = """
            SELECT 1 FROM INFORMATION_SCHEMA.TABLES 
            WHERE TABLE_NAME = ? AND TABLE_SCHEMA = 'dbo'
        """
        if not run_query(chosen_db, check_sql, [table_name]):
            raise Exception("Table not found")
        
    # Build a safe, simple SELECT with TOP and equality filters only
    sql = f"SELECT TOP (?) * FROM dbo.{table_name} WHERE 1=1"
    params: List[Any] = [limit]

    if filters:
        # Simple equality filters only (no dynamic operators), parametrized to avoid injection
        for col, val in filters.items():
            # Optional: whitelist columns per table, if you want even tighter control
            sql += f" AND {col} = ?"
            params.append(val)

    # Default ORDER BY first column to keep deterministic-ish 
    sql += " ORDER BY 1"

    rows = run_query(chosen_db, sql, params)
    return {"database": chosen_db, "table": table_name, "count": len(rows), "rows": rows}

#==============================
# Testing out connection 
#==============================
class PingIn(BaseModel):
    message: str

@mcp.tool()
def ping(message: Annotated[str, Field(description="Text to echo")]) -> dict:
    req_id = str(uuid.uuid4())
    t0 = time.time()
    logger.info("ping start req_id=%s message=%r", req_id, message)
    out = {"echo": message, "req_id": req_id, "server_ts": time.time()}
    logger.info("ping done  req_id=%s ms=%.1f out=%s",
                req_id, (time.time()-t0)*1000, json.dumps(out))
    return out

#==============================================
# Azure Blob Storage Methods
#==============================================

ALLOWED_CONTAINERS = {
    "technical-drawings"
}


# Check if container is allowed
def check_container_allowed(container: str):
    if container not in ALLOWED_CONTAINERS:
        raise PermissionError(f"Container not allowed: {container}")
    
# Get credentials 
azure_connection_string = os.getenv("AZURE_CONNECTION_STRING", "").strip()
azure_account_name = os.getenv('AZURE_ACCOUNT_NAME', "").strip()
azure_account_key = os.getenv('AZURE_ACCOUNT_KEY', "").strip()


BLOB = BlobServiceClient.from_connection_string(azure_connection_string)


def _make_read_sas(container: str, blob: str, minutes: int) -> str:
    if not (azure_account_name and azure_account_key):
        raise RuntimeError("SAS minting requires AZURE_STORAGE_ACCOUNT_NAME & AZURE_STORAGE_ACCOUNT_KEY")
    start  = datetime.utcnow() - timedelta(minutes=2)
    expiry = datetime.utcnow() + timedelta(minutes=minutes)
    sas = generate_blob_sas(
        account_name=azure_account_name,
        container_name=container,
        blob_name=blob,
        account_key=azure_account_key,
        permission=BlobSasPermissions(read=True),
        start=start, expiry=expiry,
        content_disposition=f'inline; filename="{os.path.basename(blob)}"'
    )
    base = f"https://{azure_account_name}.blob.core.windows.net"
    return f"{base}/{container}/{blob}?{sas}"


@mcp.tool()
def list_pdfs(limit: int = 25) -> dict:
    container = "technical-drawings"
    check_container_allowed(container)
    blobs = BLOB.get_container_client(container).list_blobs()
    items = [b.name for i, b in enumerate(blobs) if i < limit]
    return {"container": container, "items": items}

@mcp.tool()
def find_pdf_partcompany(
    bomkey: Annotated[str, Field(description="e.g. 11427_1")],
    with_image: Annotated[bool, Field(description="Return first page as image (base64)")] = False,
    minutes: Annotated[int, Field(ge=1, le=7*24*60, description="SAS validity in minutes")] = 1440,
) -> dict:    
    container = "technical-drawings"
    check_container_allowed(container)
    container_client = BLOB.get_container_client(container)

    # List all blobs that start with or contain the BOM key
    matches: List[Dict[str, Any]] = []
    for blob in container_client.list_blobs():
        if bomkey in blob.name and blob.name.lower().endswith(".pdf"):
            matches.append({
                "name": blob.name,
                "last_modified": getattr(blob, "last_modified", None),
                "size": getattr(blob, "size", None)
            })

    if not matches:
        return {"found": False, "reason": f"No PDFs found for BOM key {bomkey}"}

    # Pick latest modified if multiple found
    matches.sort(key=lambda x: x["last_modified"] or datetime.min, reverse=True)
    chosen = matches[0]
    blob_path = chosen["name"]

    # Generate temporary SAS URL
    sas_url = _make_read_sas(container, blob_path, minutes)
    result = {
        "found": True,
        "bomkey": bomkey,
        "container": container,
        "blob": blob_path,
        "sas_url": sas_url,
        "expires_in_minutes": minutes,
    }

    # if with_image:
    #     blob_client = BLOB.get_blob_client(container=container, blob=blob_path)
    #     data = blob_client.download_blob().readall()
    #     doc = fitz.open(stream=data, filetype="pdf")
    #     page = doc.load_page(0)
    #     pix = page.get_pixmap(matrix=fitz.Matrix(2, 2))  # higher scale = better res
    #     img_b64 = base64.b64encode(pix.tobytes("png")).decode("utf-8")
    #     result["preview_base64"] = img_b64
    
    return result

# ---------------------------------------------------
# Tool to get IP address to add to firewall protection
# ---------------------------------------------------
@mcp.tool()
def get_my_ip() -> dict:
    """Returns the server's public IP address"""
    import socket
    import requests
    
    try:
        # Get public IP
        ip = requests.get('https://api.ipify.org').text
        return {"public_ip": ip}
    except Exception as e:
        return {"error": str(e)}
# ---------------------------------------------------------
# Start MCP HTTP server
# ---------------------------------------------------------
if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=port)