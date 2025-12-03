from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="PayloadFactoryUX API",
    description="Backend for Vulnerability Scanner and Patch Generator",
    version="1.0.0"
)

# CORS Configuration
origins = [
    "http://localhost:3000",  # Next.js frontend
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from server.app.api import routes

app.include_router(routes.router)

@app.get("/")
async def root():
    return {"message": "PayloadFactoryUX API is running"}

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
