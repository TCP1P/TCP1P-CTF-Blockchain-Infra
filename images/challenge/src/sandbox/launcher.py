import os
import re
import logging
import traceback
import requests
from functools import wraps
from typing import Callable, Any
import websockets
from websockets.client import connect
import asyncio
import json
import os.path

from flask import Flask, Response, request, session, send_file, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sock import Sock

from .env import SESSION_COOKIE_NAME, SECRET_KEY # type: ignore
from .ppow import Challenge, check
from .blockchain_manager import BLOCKCHAIN_MANAGER, NodeInfo, instance_exists, load_instance, team_instance_exists

class AppConfig:
    """Centralized application configuration"""
    # Network settings
    HTTP_PORT = int(os.getenv("HTTP_PORT", 8545))
    LAUNCHER_PORT = int(os.getenv("LAUNCHER_PORT", 8546))
    ORIGIN = os.getenv("ORIGIN", "http://localhost")
    
    # Security settings
    SECRET_KEY = SECRET_KEY
    SESSION_COOKIE_NAME = SESSION_COOKIE_NAME
    DISABLE_TICKET = os.getenv("DISABLE_TICKET", "false").lower() == "true"
    FLAG = os.getenv("FLAG", "PCTF{placeholder}")
    CHALLENGE_LEVEL = int(os.getenv("CHALLENGE_LEVEL", 10000))
    RATE_LIMIT = os.getenv("RATE_LIMIT", "360 per minute")
    
    # Validation patterns
    UUID_PATTERN = re.compile(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')
    ALPHANUMERIC_PATTERN = re.compile(r'^[a-zA-Z0-9]{1,}$')
    
    # Blockchain method restrictions
    BLOCKCHAIN_RULES = {
        "eth": {
            "allowed_namespaces": ["web3", "eth", "net"],
            "blocked_methods": ["eth_sendUnsignedTransaction"]
        },
        "cairo": {
            "allowed_namespaces": ["starknet"],
            "blocked_methods": []
        },
        "solana": {
            "blocked_namespaces": ["requestAirdrop"],
            "blocked_methods": []
        }
    }
    
    # Security headers
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        # "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }

config = AppConfig()

# Flask application setup
app = Flask(__name__, static_folder="frontend", static_url_path="/static")
sock = Sock(app)
app.secret_key = config.SECRET_KEY
app.config['SESSION_COOKIE_NAME'] = config.SESSION_COOKIE_NAME
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Rate limiting setup
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[config.RATE_LIMIT],
    storage_uri="memory://",
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BlockchainGateway")

# Decorators and helpers
def validate_session(f):
    """Validate session ticket presence"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not config.DISABLE_TICKET and not session.get("ticket"):
            return error_response("Authentication required", 401)
        return f(*args, **kwargs)
    return wrapper

def error_response(message: str, code: int = 400) -> Response:
    """Standard error response format"""
    return jsonify({
        "success": False,
        "error": message,
        "code": code
    }), code

def jsonrpc_error(code: int, message: str, request_id: Any = None) -> Response:
    """JSON-RPC error response format"""
    return jsonify({
        "jsonrpc": "2.0",
        "error": {"code": code, "message": message},
        "id": request_id
    })

# Request lifecycle handlers
@app.before_request
def initialize_session():
    """Initialize session with challenge and ticket"""
    if config.DISABLE_TICKET and "ticket" not in session:
        session["ticket"] = os.urandom(16).hex()
        
    if "challenge" not in session:
        session["challenge"] = str(Challenge.generate(config.CHALLENGE_LEVEL))

@app.after_request
def add_security_headers(response: Response) -> Response:
    """Add security headers to all responses"""
    for header, value in config.SECURITY_HEADERS.items():
        response.headers[header] = value
    return response

# Core application routes
@app.route("/solution", methods=["POST"])
@limiter.limit("5 per minute")
def handle_solution():
    """Process proof-of-work challenge solution"""
    try:
        solution = request.json.get("solution", "")
        challenge = Challenge.from_string(session["challenge"])
        
        if not check(challenge, solution):
            raise ValueError("Invalid solution")
            
        session["ticket"] = os.urandom(16).hex()
        session.pop("challenge", None)
        return jsonify({"message": "Challenge solved successfully"})
        
    except Exception as e:
        session["challenge"] = str(Challenge.generate(config.CHALLENGE_LEVEL))
        logger.warning(f"Challenge failed: {str(e)}")
        return error_response("Challenge verification failed", 401)

@app.route("/launch", methods=["POST"])
@validate_session
@limiter.limit("6 per minute")
async def launch_instance():
    """Handle blockchain instance launch"""
    try:
        deploy_handler = app.config.get("DEPLOY_HANDLER")
        if not deploy_handler:
            raise RuntimeError("Deployment handler not configured")
            
        node_info = await BLOCKCHAIN_MANAGER.start_instance(session["ticket"], deploy_handler)
        session["data"] = generate_session_data(node_info)
        return jsonify({
            "success": True,
            **session["data"],
        })
        
    except Exception as e:
        traceback.print_exc()
        logger.error(f"Instance launch failed: {str(e)}")
        return error_response(f"Instance launch failed: {str(e)}", 500)

@app.route("/kill", methods=["POST"])
@validate_session
def kill_instance():
    """Terminate blockchain instance"""
    try:
        BLOCKCHAIN_MANAGER.terminate_instance(session["ticket"])
        session["data"] = None
        return jsonify({
            "success": True,
            "message": "Instance terminated successfully"
        })
        
    except Exception as e:
        logger.error(f"Instance termination failed: {str(e)}")
        return error_response(f"Instance termination failed: {str(e)}", 500)

@app.route("/flag")
@validate_session
@limiter.limit("6 per minute")
async def get_flag():
    """Retrieve flag after successful challenge solution"""
    try:
        if not await BLOCKCHAIN_MANAGER.verify_solution(session["ticket"]):
            return error_response("Challenge not solved yet", 403)
            
        return jsonify({
            "success": True,
            "flag": config.FLAG,
            "message": "Congratulations!"
        })
        
    except Exception as e:
        logger.error(f"Flag retrieval failed: {str(e)}")
        return error_response("Flag verification failed", 500)

@app.route("/<uuid:uuid>", methods=["POST"])
@limiter.exempt
def proxy_request(uuid: str):
    """Proxy HTTP requests to blockchain nodes"""
    try:
        data = request.get_json()
        blockchain_type = BLOCKCHAIN_MANAGER.blockchain_type
        rules = config.BLOCKCHAIN_RULES.get(blockchain_type, {})
        
        # Validate JSON-RPC request
        if not data or "method" not in data:
            return jsonrpc_error(-32600, "Invalid request", data.get("id"))
            
        # Validate method permissions
        method = data["method"]
        if blockchain_type == "eth":
            allowed = any(method.startswith(ns) for ns in rules["allowed_namespaces"])
            blocked = method in rules["blocked_methods"]
            if not allowed or blocked:
                return jsonrpc_error(-32601, "Method not allowed", data.get("id"))
                
        elif blockchain_type == "solana":
            if any(method.startswith(ns) for ns in rules["blocked_namespaces"]):
                return jsonrpc_error(-32601, "Method not allowed", data.get("id"))
        
        # Forward request to node
        if not instance_exists(uuid):
            return jsonrpc_error(-32602, "Invalid instance ID", data.get("id"))
            
        node_info = load_instance(uuid)
        response = requests.post(
            f"http://127.0.0.1:{node_info.port}/",
            json=data,
            timeout=10
        )
        
        return Response(
            response.content,
            status=response.status_code,
            headers=dict(response.headers)
        )
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Node communication error: {str(e)}")
        return jsonrpc_error(-32000, "Backend service unavailable", data.get("id"))

@sock.route("/<uuid:uuid>")
@limiter.limit("240 per minute")
async def proxy_websocket(ws: websockets.WebSocketServerProtocol, uuid: str):
    """Proxy WebSocket connections to blockchain nodes"""
    try:
        if not instance_exists(uuid) or BLOCKCHAIN_MANAGER.blockchain_type != "solana":
            ws.send(json.dumps({
                "jsonrpc": "2.0",
                "error": {"code": -32602, "message": "Invalid instance ID"},
                "id": None
            }))
            return

        node_info = load_instance(uuid)
        blockchain_type = BLOCKCHAIN_MANAGER.blockchain_type
        rules = config.BLOCKCHAIN_RULES.get(blockchain_type, {})

        async with connect(f"ws://127.0.0.1:{int(node_info.port)+1}/") as node_ws:
            while True:
                message = ws.receive()
                data = json.loads(message)
                
                # Validate method permissions
                if "method" in data:
                    method = data["method"]
                    if blockchain_type == "solana":
                        if any(method.startswith(ns) for ns in rules["blocked_namespaces"]):
                            ws.send(json.dumps({
                                "jsonrpc": "2.0",
                                "error": {"code": -32601, "message": "Method not allowed"},
                                "id": data.get("id")
                            }))
                            continue
                
                try:
                    await asyncio.wait_for(node_ws.send(message), timeout=1)
                    message = await asyncio.wait_for(node_ws.recv(), timeout=1)
                    ws.send(message)
                except asyncio.TimeoutError:
                    logger.warning("WebSocket operation timed out after 1 seconds")
                    continue
                except Exception as e:
                    logger.error(f"WebSocket operation error: {str(e)}")
                    continue

    except Exception as e:
        logger.error(f"WebSocket proxy error: {str(e)}")
        traceback.print_exc()
        try:
            await ws.send(json.dumps({
                "jsonrpc": "2.0",
                "error": {"code": -32000, "message": "Backend service unavailable"},
                "id": None
            }))
        except:
            pass

# Supporting routes
@app.route("/data")
def get_instance_data():
    """Retrieve instance metadata"""
    return jsonify(session.get("data", {}))

@app.route("/status")
@validate_session
def get_instance_status():
    """Check if an instance is running for the current session"""
    try:
        running = team_instance_exists(session["ticket"])
        return jsonify({
            "success": True,
            "running": running
        })
    except Exception as e:
        logger.error(f"Status check failed: {str(e)}")
        return error_response(f"Status check failed: {str(e)}", 500)

@app.route("/challenge")
def get_current_challenge():
    """Get current proof-of-work challenge"""
    return jsonify({"challenge": session.get("challenge")})

@app.route("/")
def serve_frontend():
    """Serve static frontend interface"""
    return send_file("frontend/index.html")

@app.route("/<path:path>")
def serve_static(path):
    """Serve static files from the frontend directory"""
    try:
        # Prevent directory traversal attacks
        if '..' in path:
            return error_response("Invalid path", 403)
            
        # Handle Next.js static files
        if path.startswith('_next/'):
            return send_from_directory("frontend", path)
            
        # Check if file exists
        file_path = os.path.join("frontend", path)
        if os.path.isfile(file_path):
            return send_file(file_path)
            
        # If it's a UUID format, return the SPA frontend
        # to let the client-side router handle it
        if config.UUID_PATTERN.match(path):
            return send_file("frontend/index.html")
            
        # Return the SPA for all other routes that don't match files
        # This allows the Next.js client-side router to handle routes
        if not path.endswith(('.html', '.css', '.js', '.json', '.ico', '.png', '.jpg', '.svg', '.woff', '.woff2')):
            return send_file("frontend/index.html")
            
        # File not found
        return send_file("frontend/404.html"), 404
    except Exception as e:
        logger.error(f"Error serving static file: {path}, error: {str(e)}")
        return error_response("Resource not found", 404)

# Helper functions
def generate_session_data(node_info: NodeInfo) -> dict:
    """Generate standardized session data structure"""
    base_data = {
        "0": {
            "RPC_URL": f"{{ORIGIN}}/{node_info.uuid}",
            "WS_URL": f"ws://{{ORIGIN}}/{node_info.uuid}/ws"
        },
        "message": "Your private blockchain has been deployed. It will automatically terminate in 30 minutes.",
    }
    
    if BLOCKCHAIN_MANAGER.blockchain_type == "solana":
        base_data.update({
            "1": {"PLAYER_KEYPAIR": node_info.accounts[1].private_key},
            "2": {"CTX_PUBKEY": node_info.accounts[2].public_key},
            "3": {"PROGRAM_ID": node_info.contract_addr},
        })
    else:
        base_data.update({
            "1": {"PRIVKEY": node_info.accounts[1].private_key},
            "2": {"SETUP_CONTRACT_ADDR": node_info.contract_addr},
            "3": {"WALLET_ADDR": node_info.accounts[1].address},
        })
    
    return base_data

# Error handlers
@app.errorhandler(404)
def not_found(e):
    return error_response("Resource not found", 404)

@app.errorhandler(500)
def internal_error(e):
    return error_response("Internal server error", 500)

@app.errorhandler(Exception)
def handle_exceptions(e):
    logger.exception(f"Unhandled exception occurred: {str(e)}")
    return error_response(f"An unexpected error occurred: {str(e)}", 500)

# Application initialization
def run_launcher(deploy_handler: Callable):
    """Initialize and run the application"""
    app.config["DEPLOY_HANDLER"] = deploy_handler
    return app