
from fastapi import FastAPI
from .import schemas, models
from .database import engine
import uvicorn
#from  .routers import blog, user, authentication

app = FastAPI()

models.Base.metadata.create_all(engine)

#app.include_router(authentication.router)
#app.include_router(blog.router)
#app.include_router(user.router)

@app.post('/blog')
def create(request: schemas.Blog):
    return request

if __name__ == "__main__":
    uvicorn.run(app)
