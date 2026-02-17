uvicorn app:app --host 0.0.0.0 --port $PORT

services:
  - type: web
    name: echoletter-backend
    env: python
    plan: free
    buildCommand: pip install -r requirements.txt
    startCommand: bash start.sh
    autoDeploy: true