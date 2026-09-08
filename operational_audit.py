from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel, Field

from app import auth, conn

router = APIRouter(prefix="/v1/operations", tags=["Operational Audit"])

def now():
    return datetime.now(timezone.utc)

def ensure_schema():
    with conn() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS sentinel_operational_events(
            id UUID PRIMARY KEY,
            source_system TEXT NOT NULL,
            module TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            action TEXT NOT NULL,
            actor_id TEXT,
            status TEXT,
            details JSONB NOT NULL DEFAULT '{}'::jsonb,
            occurred_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL
        )''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_sentinel_ops_time ON sentinel_operational_events(occurred_at DESC)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_sentinel_ops_entity ON sentinel_operational_events(entity_type,entity_id)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_sentinel_ops_source ON sentinel_operational_events(source_system,module)')

class OperationalEventIn(BaseModel):
    source_system: str = Field(min_length=2, max_length=80)
    module: str = Field(min_length=2, max_length=80)
    entity_type: str = Field(min_length=2, max_length=80)
    entity_id: str = Field(min_length=1, max_length=160)
    action: str = Field(min_length=2, max_length=120)
    actor_id: str | None = Field(default=None, max_length=160)
    status: str | None = Field(default=None, max_length=80)
    details: dict = {}
    occurred_at: datetime | None = None

@router.post('/events', status_code=201)
def append_event(body: OperationalEventIn, authorization: str | None = Header(None)):
    auth('sentinel.alerts.write', authorization)
    ensure_schema()
    with conn() as c:
        return c.execute('''INSERT INTO sentinel_operational_events
            (id,source_system,module,entity_type,entity_id,action,actor_id,status,details,occurred_at,created_at)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *''',
            (str(uuid4()),body.source_system,body.module,body.entity_type,body.entity_id,body.action,body.actor_id,body.status,body.details,body.occurred_at or now(),now())).fetchone()

@router.get('/events')
def list_events(source_system: str | None = None, module: str | None = None, entity_type: str | None = None, entity_id: str | None = None, limit: int = 200, authorization: str | None = Header(None)):
    auth('sentinel.alerts.read', authorization)
    ensure_schema()
    limit=max(1,min(limit,1000))
    clauses=[]; args=[]
    for col,val in [('source_system',source_system),('module',module),('entity_type',entity_type),('entity_id',entity_id)]:
        if val:
            clauses.append(f'{col}=%s'); args.append(val)
    where=(' WHERE '+' AND '.join(clauses)) if clauses else ''
    args.append(limit)
    with conn() as c:
        return c.execute('SELECT * FROM sentinel_operational_events'+where+' ORDER BY occurred_at DESC LIMIT %s',tuple(args)).fetchall()

@router.get('/timeline/{entity_type}/{entity_id}')
def timeline(entity_type: str, entity_id: str, authorization: str | None = Header(None)):
    auth('sentinel.alerts.read', authorization)
    ensure_schema()
    with conn() as c:
        return c.execute('''SELECT * FROM sentinel_operational_events
            WHERE entity_type=%s AND entity_id=%s ORDER BY occurred_at ASC''',(entity_type,entity_id)).fetchall()

@router.get('/summary')
def summary(authorization: str | None = Header(None)):
    auth('sentinel.alerts.read', authorization)
    ensure_schema()
    with conn() as c:
        return {
            'events': c.execute('SELECT COUNT(*) n FROM sentinel_operational_events').fetchone()['n'],
            'systems': c.execute('SELECT COUNT(DISTINCT source_system) n FROM sentinel_operational_events').fetchone()['n'],
            'modules': c.execute('SELECT COUNT(DISTINCT module) n FROM sentinel_operational_events').fetchone()['n'],
            'entities': c.execute("SELECT COUNT(DISTINCT entity_type || ':' || entity_id) n FROM sentinel_operational_events").fetchone()['n'],
            'generated_at': now(),
        }
