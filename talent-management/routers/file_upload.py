from fastapi import APIRouter, File, UploadFile, Depends, HTTPException
from datetime import datetime
import pandas as pd
from io import BytesIO
from database import collections
from utils.security import get_current_user

router = APIRouter()

@router.post("/employees")
async def upload_career_velocity(
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user)
):
    if current_user["role"] != "Admin":
        raise HTTPException(403, "Only Admin can upload")

    content = await file.read()
    df = pd.read_excel(BytesIO(content))

    required = ["Employee ID", "Employee Name", "Designation", "Band", "City", "Type"]
    if not all(col in df.columns for col in required):
        raise HTTPException(400, "Invalid columns")

    records = []
    for _, row in df.iterrows():
        skills = str(row.get("Detailed Skill Set (List of top skills on profile)", "")).split(", ")
        skills = [s.strip() for s in skills if s.strip() and s.strip().lower() != "not available"]

        record = {
            "employee_id": int(row["Employee ID"]),
            "name": row["Employee Name"],
            "designation": row["Designation"],
            "band": row["Band"],
            "city": row["City"],
            "location": row.get("Location Description", ""),
            "primary_technology": row.get("Primary Technology", ""),
            "secondary_technology": row.get("Secondary Technology", ""),
            "skills": skills,
            "type": row["Type"].strip(),
            "updated_at": datetime.utcnow()
        }
        records.append(record)

    # Upsert employees
    for rec in records:
        await collections["employees"].update_one(
            {"employee_id": rec["employee_id"]},
            {"$set": rec},
            upsert=True
        )

    await collections["audit_logs"].insert_one({
        "action": "upload_employees",
        "uploaded_by": current_user["employee_id"],
        "count": len(records),
        "timestamp": datetime.utcnow()
    })

    return {"message": f"{len(records)} employees processed"}

@router.post("/rr-report")
async def upload_rr_report(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "Admin":
        raise HTTPException(403, "Only Admin")

    content = await file.read()
    df = pd.read_excel(BytesIO(content), skiprows=6)  # Skip header junk

    existing_rr_ids = {j async for j in collections["jobs"].find({}, {"rr_id": 1})}

    new_jobs = []
    current_rr_ids = set()

    for _, row in df.iterrows():
        rr_id = str(row["Resource Request ID"])
        current_rr_ids.add(rr_id)

        if rr_id in existing_rr_ids:
            continue  # Already exists

        job = {
            "rr_id": rr_id,
            "title": str(row["UST - Role"]),
            "location": f"{row['City']}, {row.get('State', '')}, {row['Country']}",
            "required_skills": [],
            "description": str(row.get("Job Description", "")),
            "start_date": pd.to_datetime(row["RR Start Date"]),
            "end_date": pd.to_datetime(row["RR End Date"]),
            "wfm_id": str(row["WFM ID"]),
            "hm_id": str(row["HM ID"]),
            "status": "Open",
            "uploaded_at": datetime.utcnow()
        }
        new_jobs.append(job)

    if new_jobs:
        await collections["jobs"].insert_many(new_jobs)

    # Close missing jobs
    missing = existing_rr_ids - current_rr_ids
    if missing:
        await collections["jobs"].update_many(
            {"rr_id": {"$in": list(missing)}},
            {"$set": {"status": "Closed"}}
        )

    return {"added": len(new_jobs), "closed": len(missing)}