#!/usr/bin/env python3
"""
Fortress On-Demand Image Sync API
"""
from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import subprocess
import logging
import uuid

app = FastAPI(title="Fortress Image Sync API")
logger = logging.getLogger(__name__)

# Image sync status tracking
sync_status = {}

# Supported images
IMAGES = {
    "trivy": "aquasec/trivy:latest",
    "syft": "anchore/syft:latest",
    "kube-bench": "aquasec/kube-bench:latest"
}

HARBOR_REGISTRY = "10.63.89.182:30500"

class ImageRequest(BaseModel):
    tool_name: str
    agent_id: str

class ImageResponse(BaseModel):
    request_id: str
    status: str
    harbor_image: str = None

def sync_image(tool_name: str, request_id: str):
    """Sync image from Docker Hub to Harbor"""
    try:
        source = IMAGES[tool_name]
        target = f"{HARBOR_REGISTRY}/security/{tool_name}:latest"
        
        # Login to Harbor
        subprocess.run(f"echo 'Harbor12345' | docker login {HARBOR_REGISTRY} -u admin --password-stdin", shell=True)
        
        # Pull, tag, push
        subprocess.run(f"docker pull {source}", shell=True, check=True)
        subprocess.run(f"docker tag {source} {target}", shell=True, check=True)
        subprocess.run(f"docker push {target}", shell=True, check=True)
        
        # Update status
        sync_status[request_id] = {"status": "ready", "harbor_image": target}
        
        # Cleanup
        subprocess.run(f"docker rmi {source} {target}", shell=True)
        
    except Exception as e:
        sync_status[request_id] = {"status": "failed", "error": str(e)}

@app.post("/request-image", response_model=ImageResponse)
async def request_image(request: ImageRequest, background_tasks: BackgroundTasks):
    """Agent requests image sync"""
    
    if request.tool_name not in IMAGES:
        return ImageResponse(request_id="", status="error")
    
    request_id = str(uuid.uuid4())
    sync_status[request_id] = {"status": "syncing"}
    
    # Start background sync
    background_tasks.add_task(sync_image, request.tool_name, request_id)
    
    return ImageResponse(
        request_id=request_id,
        status="syncing",
        harbor_image=f"{HARBOR_REGISTRY}/security/{request.tool_name}:latest"
    )

@app.get("/status/{request_id}")
async def get_status(request_id: str):
    """Check sync status"""
    return sync_status.get(request_id, {"status": "not_found"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
