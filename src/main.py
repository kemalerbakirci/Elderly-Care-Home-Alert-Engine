"""
main.py

Main entry point for the Elderly Care Home Alert Engine.
Initializes FastAPI app and starts the MQTT listener engine in a background thread.
"""

from fastapi import FastAPI
from .routes import router as api_router
from .mqtt_listener import start_mqtt_thread

app = FastAPI(
    title="Elderly Care Home Alert Engine",
    description="Monitors motion, bed, and bathroom sensors to detect elderly emergencies in real time.",
    version="1.0.0"
)

# Register API endpoints
app.include_router(api_router)

# Start MQTT on app startup
@app.on_event("startup")
def startup_event():
    print("🚀 Starting Elderly Care Home Alert Engine...")
    start_mqtt_thread()
    print("✅ MQTT listener running in background.")

# Optional health check endpoint
@app.get("/")
def read_root():
    return {"status": "ok", "message": "Elderly Care Engine is running."}