from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone
from uuid import uuid4

app=FastAPI(title='UNG-SENTINEL',version='0.1.0')
alerts=[]
incidents=[]

def now(): return datetime.now(timezone.utc).isoformat()
def auth(p,h):
 perms={x.strip() for x in (h or '').split(',') if x.strip()}
 if p not in perms and 'ung.admin' not in perms: raise HTTPException(403,'UNG-JANUS permission required')

class AlertIn(BaseModel):
 source:str
 severity:str
 title:str
 details:str=''

class IncidentIn(BaseModel):
 alert_id:str|None=None
 title:str
 severity:str='medium'

@app.get('/')
def root(): return {'system':'UNG-SENTINEL','domain':'security-operations-center','status':'online','version':'0.1.0'}
@app.get('/health')
def health(): return {'status':'ok','service':'UNG-SENTINEL','version':'0.1.0'}
@app.get('/ready')
def ready(): return {'status':'ready','service':'UNG-SENTINEL'}
@app.get('/v1/system')
def system(): return {'system_id':'UNG-SENTINEL','domain':'security-operations-center','capabilities':['alerts','incidents','triage','security-monitoring']}
@app.get('/v1/alerts')
def list_alerts(x_ung_permissions:str|None=Header(None)):
 auth('sentinel.alerts.read',x_ung_permissions); return alerts
@app.post('/v1/alerts',status_code=201)
def create_alert(body:AlertIn,x_ung_permissions:str|None=Header(None)):
 auth('sentinel.alerts.write',x_ung_permissions); r={'id':str(uuid4()),**body.model_dump(),'status':'open','created_at':now()}; alerts.append(r); return r
@app.get('/v1/incidents')
def list_incidents(x_ung_permissions:str|None=Header(None)):
 auth('sentinel.incidents.read',x_ung_permissions); return incidents
@app.post('/v1/incidents',status_code=201)
def create_incident(body:IncidentIn,x_ung_permissions:str|None=Header(None)):
 auth('sentinel.incidents.write',x_ung_permissions); r={'id':str(uuid4()),**body.model_dump(),'status':'investigating','created_at':now()}; incidents.append(r); return r
@app.get('/v1/summary')
def summary(x_ung_permissions:str|None=Header(None)):
 auth('sentinel.alerts.read',x_ung_permissions); return {'open_alerts':sum(x['status']=='open' for x in alerts),'active_incidents':sum(x['status']=='investigating' for x in incidents),'generated_at':now()}
