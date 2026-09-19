from fastapi import FastAPI,Header,HTTPException
from pydantic import BaseModel
from datetime import datetime,timezone,timedelta
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
  c.execute("""CREATE TABLE IF NOT EXISTS vault_ingest_nonces(
    nonce TEXT PRIMARY KEY,
    sent_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )""")
  c.execute("CREATE INDEX IF NOT EXISTS ix_vault_ingest_nonces_received ON vault_ingest_nonces(received_at DESC)")
  c.execute("""CREATE TABLE IF NOT EXISTS vault_ingest_events(
    event_id TEXT PRIMARY KEY,
    alert_id UUID NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now()
  )""")
  c.execute("CREATE INDEX IF NOT EXISTS ix_vault_ingest_events_received ON vault_ingest_events(received_at DESC)")
@app.on_event('startup')
def startup():
 print(f"SENTINEL_CONFIG database={'configured' if bool(DB) else 'missing'} vault_ingest={'configured' if bool(VAULT_INGEST_SECRET) else 'missing'}")
 init_db()
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
 sent_at:str
 nonce:str
 event_id:str
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
def system():return {'system_id':'UNG-SENTINEL','domain':'security-operations-center','capabilities':['alerts','incidents','acknowledgement','resolution','closure','operational-audit-events','entity-timelines','global-activity-feed','janus-bearer-auth','postgresql','signed-ingest-replay-protection','vault-military-auto-incidents','vault-event-idempotency']}
def vault_signature_ok(payload:dict,signature:str|None)->bool:
 if not VAULT_INGEST_SECRET:return False
 raw=json.dumps(payload,sort_keys=True,separators=(',',':')).encode()
 expected=hmac.new(VAULT_INGEST_SECRET.encode(),raw,hashlib.sha256).hexdigest()
 return bool(signature and hmac.compare_digest(expected,signature))

def verify_vault_freshness_and_nonce(c,payload:dict)->None:
 try:
  sent=datetime.fromisoformat(str(payload.get('sent_at','')).replace('Z','+00:00'))
  if sent.tzinfo is None:sent=sent.replace(tzinfo=timezone.utc)
 except Exception:
  raise HTTPException(400,'invalid_vault_sent_at')
 age=(now()-sent).total_seconds()
 if age>300 or age < -60:raise HTTPException(401,'stale_or_future_vault_event')
 nonce=str(payload.get('nonce') or '').strip()
 if len(nonce)<16 or len(nonce)>200:raise HTTPException(400,'invalid_vault_nonce')
 event_id=str(payload.get('event_id') or '').strip()
 if len(event_id)<8 or len(event_id)>200:raise HTTPException(400,'invalid_vault_event_id')
 c.execute("DELETE FROM vault_ingest_nonces WHERE received_at < now() - interval '24 hours'")
 c.execute("DELETE FROM vault_ingest_events WHERE received_at < now() - interval '30 days'")
 try:
  c.execute("INSERT INTO vault_ingest_nonces(nonce,sent_at) VALUES(%s,%s)",(nonce,sent))
 except psycopg.errors.UniqueViolation:
  raise HTTPException(409,'replayed_vault_event')

@app.post('/v1/ingest/vault',status_code=201)
def ingest_vault_event(b:VaultEventIn,x_ung_vault_signature:str|None=Header(None)):
 if not VAULT_INGEST_SECRET:raise HTTPException(503,'vault_ingest_not_configured')
 if b.severity not in {'low','medium','high','critical'}:raise HTTPException(400,'invalid_severity')
 if not vault_signature_ok(b.model_dump(),x_ung_vault_signature):
  raise HTTPException(401,'invalid_vault_signature')
 detail={
  'event_type':b.event_type,
  'session_id':b.session_id,
  'object_id':b.object_id,
  'owner':b.owner,
  'details':b.details,
 }
 with conn() as c:
  verify_vault_freshness_and_nonce(c,b.model_dump())
  prior=c.execute("""SELECT e.event_id,e.alert_id,a.* FROM vault_ingest_events e
                     JOIN sentinel_alerts a ON a.id=e.alert_id
                     WHERE e.event_id=%s""",(b.event_id,)).fetchone()
  if prior:
   prior['incident']=None
   prior['auto_incident_opened']=False
   prior['duplicate_event']=True
   return prior
  row=c.execute("INSERT INTO sentinel_alerts VALUES(%s,%s,%s,%s,%s,'open',%s,%s) RETURNING *",
   (str(uuid4()),b.source,b.severity,b.title,json.dumps(detail,separators=(',',':')),now(),now())).fetchone()
  c.execute("INSERT INTO vault_ingest_events(event_id,alert_id) VALUES(%s,%s)",(b.event_id,str(row['id'])))
  incident=None
  military_auto_incident={
   'military_record_deleted',
   'military_file_redacted_release',
   'military_release_fully_approved',
  }
  should_open_incident=(b.severity=='critical') or (b.severity=='high' and b.event_type in military_auto_incident)
  if should_open_incident:
   incident_severity='critical' if b.severity=='critical' else 'high'
   incident=c.execute("INSERT INTO sentinel_incidents VALUES(%s,%s,%s,%s,'investigating',%s,%s) RETURNING *",
    (str(uuid4()),str(row['id']),'VAULT: '+b.title,incident_severity,now(),now())).fetchone()
 row['incident']=incident
 row['auto_incident_opened']=bool(incident)
 return row

@app.post('/v1/ingest/vault/probe')
def probe_vault_event(b:VaultEventIn,x_ung_vault_signature:str|None=Header(None)):
 if not VAULT_INGEST_SECRET:raise HTTPException(503,'vault_ingest_not_configured')
 if not vault_signature_ok(b.model_dump(),x_ung_vault_signature):
  raise HTTPException(401,'invalid_vault_signature')
 with conn() as c:
  verify_vault_freshness_and_nonce(c,b.model_dump())
 return {'ok':True,'channel':'UNG-VAULT->UNG-SENTINEL','replay_protection':True}

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
