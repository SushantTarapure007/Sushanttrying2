from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from typing import List
from enum import Enum

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Role(str, Enum):
    admin = "admin"
    editor = "editor"
    viewer = "viewer"

# Mock database of users with roles
users_db = {
    "user1": {"username": "user1", "role": Role.admin},
    "user2": {"username": "user2", "role": Role.editor},
    "user3": {"username": "user3", "role": Role.viewer},
}

def get_current_user(token: str = Depends(oauth2_scheme)):
    # In a real application, you would decode the token to get the user information
    user = users_db.get(token)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
        )
    return user

def get_user_role(current_user: dict = Depends(get_current_user)):
    return current_user["role"]

def check_permissions(required_role: Role):
    def role_checker(user_role: Role = Depends(get_user_role)):
        if user_role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
    return role_checker

# Define endpoints with access control

@app.post("/create", dependencies=[Depends(check_permissions(Role.admin))])
def create_item():
    return {"message": "Item created"}

@app.get("/read", dependencies=[Depends(check_permissions(Role.viewer))])
def read_item():
    return {"message": "Item read"}

@app.put("/update", dependencies=[Depends(check_permissions(Role.editor))])
def update_item():
    return {"message": "Item updated"}

@app.delete("/delete", dependencies=[Depends(check_permissions(Role.admin))])
def delete_item():
    return {"message": "Item deleted"}

# Token endpoint for the example
@app.post("/token")
def login(username: str):
    if username not in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user",
        )
    return {"access_token": username, "token_type": "bearer"}