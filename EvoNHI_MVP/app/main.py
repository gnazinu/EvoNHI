from fastapi import FastAPI

from app.api.routes import router
from app.db import Base, engine

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="EvoNHI SaaS MVP",
    version="0.1.0",
    description="SaaS-first MVP for non-human identity attack path reduction.",
)


@app.get("/health")
def healthcheck():
    return {"status": "ok", "service": "evonhi-saas"}


app.include_router(router)
