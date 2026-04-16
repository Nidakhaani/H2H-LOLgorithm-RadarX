"""
FastAPI Backend Module
"""
try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
except ImportError:
    import sys
    print("❌ FastAPI not installed. Run: pip install -r requirements.txt")
    # For standalone stubs to partially execute or fail gracefully
    FastAPI = lambda title, version: None
    JSONResponse = None

app = FastAPI(title="RadarX API", version="1.0.0") if FastAPI else None

if app:
    @app.get("/api/health")
    async def health_check():
        """Basic health check endpoint"""
        try:
            return {"status": "ok", "app": "RadarX", "version": "1.0.0"}
        except Exception as e:
            if JSONResponse:
                return JSONResponse(status_code=500, content={"status": "error", "message": str(e)})
            return {"status": "error", "message": str(e)}

if __name__ == "__main__":
    try:
        import uvicorn
        print("🚀 Starting standalone FastAPI server...")
        if app:
            uvicorn.run(app, host="0.0.0.0", port=8000)
    except ImportError:
        print(f"❌ Uvicorn not installed. Please run: pip install -r requirements.txt")
    except Exception as e:
        print(f"❌ Server crashed: {str(e)}")
