from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

from routers import auth, file_upload, job, employee, application, manager_workflow, admin, admin_logs

app = FastAPI(title="Talent Management System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB Connection
client = AsyncIOMotorClient("mongodb+srv://303391_db_user:5IhrghdRaiXTR22b@cluster0.i0ih74y.mongodb.net/?appName=Cluster0")
db = client.talent_management

app.include_router(auth.router, tags=["Auth"])
app.include_router(admin.router, tags=["Admin"])
app.include_router(file_upload.router, prefix="/api/upload", tags=["File Upload"])
app.include_router(job.router, prefix="/api/jobs", tags=["Jobs"])
app.include_router(employee.router, prefix="/api/employees", tags=["Employees"])
app.include_router(application.router, prefix="/api/applications", tags=["Applications"])
app.include_router(manager_workflow.router, prefix="/api/manager", tags=["Manager Workflow"])
app.include_router(admin_logs.router,prefix="/api/admin/activity", tags=["Admin Logs"])

@app.get("/")
def root():
    return {"message": "Talent Management System API"}