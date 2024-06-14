from fastapi import FastAPI
from fastapi.responses import JSONResponse


app = FastAPI()

@app.get('/')
async def healthchecheck():
    return JSONResponse(content={"name": "sushant tarapure"})