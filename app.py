from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel
from datetime import datetime,timezone
from uuid import uuid4
import json,os,psycopg,urllib.error,urllib.request,hashlib,hmac
from psycopg.rows import dict_row
app=FastAPI(title='UNG-SENTINEL',version='0.4.0')
DB=os.getenv('DATABASE_URL','');JANUS=os.getenv('JANUS_BASE_URL','https://ung-iam-production.up.railway.app').rstrip('/')
VAULT_INGEST_SECRET=os.getenv('VAULT_INGEST_SECRET','')
def now():return datetime.now(timezone.utc)
def auth(p,h):
 if not h or not h.lower().startswith('bearer '):raise HTTPException(401,'JANUS bearer token required')
 req=urllib.request.Request(JANUS+'/v1/auth/introspect',data=b'',method='POST',headers={'Authorization':h})
 try:
  with urllib.request.urlopen(req,timeout=5) as r:d=json.loads(r.read().decode())
 except urllib.error.HTTPError as e:
  if e.code in (401,403):raise HTTPException(401,'JANUS token invalid or expired')
  raise HTTPException(503,'JANUS authorization unavailable')
 except Exception:raise HTTPException(503,'JANUS authorization unavailable')
 perms=set((d.get('principal') or {}).get('permissions') or [])
 if p not in perms and 'ung.admin' not in perms:raise HTTPException(403,f'Missing JANUS permission: {p}')
def conn():
 if not DB:raise HTTPException(503,'database_not_configured')
 return psycopg.connect(DB,row_factory=dict_row)
def init_db():
 if not DB:return
 with conn() as c:
  c.execute("CREATE TABLE IF NOT EXISTS sentinel_alerts(id UUID PRIMARY KEY,source TEXT NOT NULL,severity TEXT NOT NULL,title TEXT NOT NULL,details TEXT NOT NULL DEFAULT '',status TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL)")
  c.execute("CREATE TABLE IF NOT EXISTS sentinel_incidents(id UUID PRIMARY KEY,alert_id UUID NULL,title TEXT NOT NULL,severity TEXT NOT NULL,status TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL)")
  c.execute('ALTER TABLE sentinel_alerts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ')
  c.execute('ALTER TABLE sentinel_incidents ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ')
@app.on_event('startup')
def startup():init_db()
class AlertIn(BaseModel):source:str;severity:str;title:str;details:str=''
class IncidentIn(BaseModel):alert_id:str|None=None;title:str;severity:str='medium'
class StateIn(BaseModel):status:str
class VaultEventIn(BaseModel):
 source:str='UNG-VAULT'
 severity:str
 title:str
 details:str=''
 event_type:str=''
 session_id:str|None=None
 object_id:str|None=None
 owner:str|None=None
@app.get('/')
def root():return {'system':'UNG-SENTINEL','domain':'security-operations-center','status':'online','version':'0.4.0'}
@app.get('/health')
def health():return {'status':'ok','service':'UNG-SENTINEL','version':'0.4.0'}
@app.get('/ready')
def ready():
 try:
  with conn() as c:c.execute('SELECT 1')
  return {'status':'ready','database':'connected','janus':JANUS}
 except Exception:return {'status':'degraded','database':'unavailable','janus':JANUS}
@app.get('/v1/system')
def system():return {'system_id':'UNG-SENTINEL','domain':'security-operations-center','capabilities':['alerts','incidents','acknowledgement','resolution','closure','operational-audit-events','entity-timelines','global-activity-feed','janus-bearer-auth','postgresql']}
@app.post('/v1/ingest/vault',status_code=201)
def ingest_vault_event(b:VaultEventIn,x_ung_vault_signature:str|None=Header(None)):
 if not VAULT_INGEST_SECRET:raise HTTPException(503,'vault_ingest_not_configured')
 if b.severity not in {'low','medium','high','critical'}:raise HTTPException(400,'invalid_severity')
 raw=json.dumps(b.model_dump(),sort_keys=True,separators=(',',':')).encode()
 expected=hmac.new(VAULT_INGEST_SECRET.encode(),raw,hashlib.sha256).hexdigest()
 if not x_ung_vault_signature or not hmac.compare_digest(expected,x_ung_vault_signature):
  raise HTTPException(401,'invalid_vault_signature')
 detail={
  'event_type':b.event_type,
  'session_id':b.session_id,
  'object_id':b.object_id,
  'owner':b.owner,
  'details':b.details,
 }
 with conn() as c:
  row=c.execute("INSERT INTO sentinel_alerts VALUES(%s,%s,%s,%s,%s,'open',%s,%s) RETURNING *",
   (str(uuid4()),b.source,b.severity,b.title,json.dumps(detail,separators=(',',':')),now(),now())).fetchone()
 return row

@app.get('/v1/alerts')
def alerts(authorization:str|None=Header(None)):
 auth('sentinel.alerts.read',authorization)
 with conn() as c:return c.execute('SELECT * FROM sentinel_alerts ORDER BY created_at DESC').fetchall()
@app.post('/v1/alerts',status_code=201)
def add_alert(b:AlertIn,authorization:str|None=Header(None)):
 auth('sentinel.alerts.write',authorization)
 if b.severity not in {'low','medium','high','critical'}:raise HTTPException(400,'invalid_severity')
 with conn() as c:return c.execute("INSERT INTO sentinel_alerts VALUES(%s,%s,%s,%s,%s,'open',%s,%s) RETURNING *",(str(uuid4()),b.source,b.severity,b.title,b.details,now(),now())).fetchone()
@app.patch('/v1/alerts/{aid}')
def update_alert(aid:str,b:StateIn,authorization:str|None=Header(None)):
 auth('sentinel.alerts.write',authorization)
 if b.status not in {'open','acknowledged','resolved','closed'}:raise HTTPException(400,'invalid_alert_status')
 with conn() as c:
  r=c.execute('UPDATE sentinel_alerts SET status=%s,updated_at=%s WHERE id=%s RETURNING *',(b.status,now(),aid)).fetchone()
  if not r:raise HTTPException(404,'alert_not_found')
  return r
@app.get('/v1/incidents')
def incidents(authorization:str|None=Header(None)):
 auth('sentinel.incidents.read',authorization)
 with conn() as c:return c.execute('SELECT * FROM sentinel_incidents ORDER BY created_at DESC').fetchall()
@app.post('/v1/incidents',status_code=201)
def add_incident(b:IncidentIn,authorization:str|None=Header(None)):
 auth('sentinel.incidents.write',authorization)
 if b.severity not in {'low','medium','high','critical'}:raise HTTPException(400,'invalid_severity')
 with conn() as c:
  if b.alert_id and not c.execute('SELECT id FROM sentinel_alerts WHERE id=%s',(b.alert_id,)).fetchone():raise HTTPException(404,'alert_not_found')
  return c.execute("INSERT INTO sentinel_incidents VALUES(%s,%s,%s,%s,'investigating',%s,%s) RETURNING *",(str(uuid4()),b.alert_id,b.title,b.severity,now(),now())).fetchone()
@app.patch('/v1/incidents/{iid}')
def update_incident(iid:str,b:StateIn,authorization:str|None=Header(None)):
 auth('sentinel.incidents.write',authorization)
 if b.status not in {'investigating','contained','resolved','closed'}:raise HTTPException(400,'invalid_incident_status')
 with conn() as c:
  r=c.execute('UPDATE sentinel_incidents SET status=%s,updated_at=%s WHERE id=%s RETURNING *',(b.status,now(),iid)).fetchone()
  if not r:raise HTTPException(404,'incident_not_found')
  return r
@app.get('/v1/summary')
def summary(authorization:str|None=Header(None)):
 auth('sentinel.alerts.read',authorization)
 with conn() as c:
  a=c.execute("SELECT count(*) n FROM sentinel_alerts WHERE status NOT IN ('resolved','closed')").fetchone()['n'];i=c.execute("SELECT count(*) n FROM sentinel_incidents WHERE status NOT IN ('resolved','closed')").fetchone()['n'];crit=c.execute("SELECT count(*) n FROM sentinel_alerts WHERE severity='critical' AND status NOT IN ('resolved','closed')").fetchone()['n']
 return {'active_alerts':a,'active_incidents':i,'critical_alerts':crit,'generated_at':now()}

from operational_audit import router as operational_router
app.include_router(operational_router)
