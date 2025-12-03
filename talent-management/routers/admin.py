# routers/admin.py
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from database import collections
from models import Employee, Job, Application, ApplicationStatus
from utils.security import get_current_user
from datetime import datetime

router = APIRouter(prefix="/api/admin", tags=["Admin"])

# Helper: Only Admin allowed
async def require_admin(user: dict = Depends(get_current_user)):
    if user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Admin access only")
    return user

# 1. View FULL audit trail
@router.get("/audit-logs")
async def get_audit_logs(admin = Depends(require_admin)):
    logs = await collections["audit_logs"].find().sort("timestamp", -1).to_list(500)
    return logs

# 2. View EVERY application in the system (bypass all manager filters)
@router.get("/applications/all", response_model=List[Application])
async def get_all_applications(admin = Depends(require_admin)):
    apps = await collections["applications"].find().sort("updated_at", -1).to_list(1000)
    return [Application(**app) for app in apps]

# 3. Create user manually (for onboarding)
@router.post("/users")
async def create_user_manual(
    employee_id: str,
    name: str,
    email: str,
    password: str,
    role: str,
    admin = Depends(require_admin)
):
    from passlib.context import CryptContext
    pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
    
    hashed = pwd_context.hash(password)
    new_user = {
        "employee_id": employee_id,
        "name": name,
        "email": email,
        "password": hashed,
        "role": role,
        "created_at": datetime.utcnow()
    }
    await collections["users"].insert_one(new_user)
    return {"message": "User created successfully"}

# 4. Admin can perform ANY workflow action (shortlist, interview, select, allocate, reject)
@router.put("/applications/{app_id}/force/{action}")
async def admin_force_action(
    app_id: str,
    action: str,  # shortlist | interview | select | reject | allocate
    admin = Depends(require_admin)
):
    valid_actions = ["shortlist", "interview", "select", "reject", "allocate"]
    if action not in valid_actions:
        raise HTTPException(400, "Invalid action")
    
    updates = {
        "shortlist": {"status": ApplicationStatus.SHORTLISTED},
        "interview": {"status": ApplicationStatus.INTERVIEW},
        "select": {"status": ApplicationStatus.SELECTED},
        "reject": {"status": ApplicationStatus.REJECTED},
        "allocate": {"status": ApplicationStatus.ALLOCATED},
    }
    
    result = await collections["applications"].update_one(
        {"_id": app_id},
        {"$set": {**updates[action], "updated_at": datetime.utcnow()}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(404, "Application not found")
    
    return {"message": f"Application {action}d by Admin"}