from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from datetime import datetime
import uuid
from database import collections
from models import Application, ApplicationStatus, UserRole
from utils.security import get_current_user

router = APIRouter()

@router.post("/")
async def create_application(app_in: Application, current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in [UserRole.EMPLOYEE_TP, UserRole.EMPLOYEE_NON_TP]:
        raise HTTPException(403)
    app_in.employee_id = current_user["employee_id"]
    app_in.id = str(uuid.uuid4())
    await collections["applications"].insert_one(app_in.dict(by_alias=True))
    return app_in

@router.put("/{app_id}")
async def update_draft(app_id: str, update_data: Application, current_user: dict = Depends(get_current_user)):
    app = await collections["applications"].find_one({"_id": app_id, "employee_id": int(current_user["employee_id"])})
    if not app or app["status"] != ApplicationStatus.DRAFT:
        raise HTTPException(400, "Cannot edit")
    await collections["applications"].update_one(
        {"_id": app_id},
        {"$set": {**update_data.dict(exclude_unset=True), "updated_at": datetime.utcnow()}}
    )
    return {"message": "Updated"}

@router.post("/{app_id}/submit")
async def submit_application(app_id: str, current_user: dict = Depends(get_current_user)):
    app = await collections["applications"].find_one({"_id": app_id, "employee_id": int(current_user["employee_id"])})
    if not app or app["status"] != ApplicationStatus.DRAFT:
        raise HTTPException(400)
    await collections["applications"].update_one(
        {"_id": app_id},
        {"$set": {"status": ApplicationStatus.SUBMITTED, "submitted_at": datetime.utcnow()}}
    )
    return {"message": "Submitted"}

@router.delete("/{app_id}")
async def withdraw(app_id: str, current_user: dict = Depends(get_current_user)):
    app = await collections["applications"].find_one({"_id": app_id, "employee_id": int(current_user["employee_id"])})
    if not app or app["status"] in [ApplicationStatus.SHORTLISTED, ApplicationStatus.INTERVIEW, ApplicationStatus.SELECTED, ApplicationStatus.ALLOCATED]:
        raise HTTPException(400, "Cannot withdraw")
    await collections["applications"].update_one(
        {"_id": app_id},
        {"$set": {"status": ApplicationStatus.WITHDRAWN}}
    )
    return {"message": "Withdrawn"}