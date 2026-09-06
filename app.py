from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone
from uuid import uuid4
import os, psycopg
from psycopg.rows import dict_row

app=FastAPI(title='UNG-SENTINEL',version='0.2.0')
DB=os.getenv('DATABASE_URL','')
def now(): return datetime.now(timezone.utc).isoformat()
def auth(p,h):
 perms={x.strip() for x in (h or '').split(',') if x.strip()}
 if p not in perms and 'ung.admin' not in perms: raise HTTPException(403,'UNG-JANUS permission required')
def conn():
 if not DB: raise HTTPException(503,'database_not_configured')
 return psycopg.connect(DB,row_factory=dict_row)
def init_db():
 if not DB:return
 with conn() as c:
  c.execute('CREATE TABLE IF NOT EXISTS sentinel_alerts (id UUID PRIMARY KEY, source TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, details TEXT NOT NULL DEFAULT \'\', status TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)')
  c.execute('CREATE TABLE IF NOT EXISTS sentinel_incidents (id UUID PRIMARY KEY, alert_id UUID NULL, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL)')
@app.on_event('startup')
def startup(): init_db()
class AlertIn(BaseModel):
 source:str; severity:str; title:str; details:str=''
class IncidentIn(BaseModel):
 alert_id:str|None=None; title:str; severity:str='medium'
@app.get('/')
def root(): return {'system':'UNG-SENTINEL','domain':'security-operations-center','status':'online','version':'0.2.0'}
@app.get('/health')
def health(): return {'status':'ok','service':'UNG-SENTINEL','version':'0.2.0'}
@app.get('/ready')
def ready():
 try:
  with conn() as c:c.execute('SELECT 1')
  return {'status':'ready','service':'UNG-SENTINEL','database':'connected'}
 except Exception:return {'status':'degraded','service':'UNG-SENTINEL','database':'unavailable'}
@app.get('/v1/system')
def system(): return {'system_id':'UNG-SENTINEL','domain':'security-operations-center','capabilities':['alerts','incidents','triage','security-monitoring','postgresql']}
@app.get('/v1/alerts')
def list_alerts(x_ung_permissions:str|None=Header(None)):
 auth('sentinel.alerts.read',x_ung_permissions)
 with conn() as c:return c.execute('SELECT * FROM sentinel_alerts ORDER BY created_at DESC').fetchall()
@app.post('/v1/alerts',status_code=201)
def create_alert(body:AlertIn,x_ung_permissions:str|None=Header(None)):
 auth('sentinel.alerts.write',x_ung_permissions); i=str(uuid4())
 with conn() as c:return c.execute('INSERT INTO sentinel_alerts(id,source,severity,title,details,status,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *',(i,body.source,body.severity,body.title,body.details,'open',now())).fetchone()
@app.get('/v1/incidents')
def list_incidents(x_ung_permissions:str|None=Header(None)):
 auth('sentinel.incidents.read',x_ung_permissions)
 with conn() as c:return c.execute('SELECT * FROM sentinel_incidents ORDER BY created_at DESC').fetchall()
@app.post('/v1/incidents',status_code=201)
def create_incident(body:IncidentIn,x_ung_permissions:str|None=Header(None)):
 auth('sentinel.incidents.write',x_ung_permissions); i=str(uuid4())
 with conn() as c:return c.execute('INSERT INTO sentinel_incidents(id,alert_id,title,severity,status,created_at) VALUES(%s,%s,%s,%s,%s,%s) RETURNING *',(i,body.alert_id,body.title,body.severity,'investigating',now())).fetchone()
@app.get('/v1/summary')
def summary(x_ung_permissions:str|None=Header(None)):
 auth('sentinel.alerts.read',x_ung_permissions)
 with conn() as c:
  a=c.execute("SELECT count(*) n FROM sentinel_alerts WHERE status='open'").fetchone()['n']; i=c.execute("SELECT count(*) n FROM sentinel_incidents WHERE status='investigating'").fetchone()['n']
 return {'open_alerts':a,'active_incidents':i,'generated_at':now()}
