import os, sqlite3, json, secrets, hashlib, hmac, time, datetime, contextlib
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

ROOT=Path(__file__).resolve().parent
DB=Path(os.getenv('SUNNY_DB',str(ROOT/'sunny.sqlite3')))
COOKIE_SECURE=os.getenv('SUNNY_HTTPS','0')=='1'
app=FastAPI(title='Sunny Travel Online v2.0 - Foundation',docs_url=None,redoc_url=None)
ROLES={'admin','manager','accountant','seller'}

def connect():
 c=sqlite3.connect(DB,timeout=10);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA journal_mode=WAL');return c

def init():
 DB.parent.mkdir(parents=True,exist_ok=True)
 with contextlib.closing(connect()) as c:
  c.executescript('''
 CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, passhash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','manager','accountant','seller')),active INTEGER NOT NULL DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS sessions(tokenhash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),expires INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS agents(id INTEGER PRIMARY KEY,code TEXT UNIQUE NOT NULL,name TEXT NOT NULL,phone TEXT DEFAULT '',active INTEGER NOT NULL DEFAULT 1,zalo_consent INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS ticket_types(id INTEGER PRIMARY KEY,code TEXT UNIQUE NOT NULL,name TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,sort_order INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS prices(id INTEGER PRIMARY KEY,agent_id INTEGER NOT NULL REFERENCES agents(id),ticket_id INTEGER NOT NULL REFERENCES ticket_types(id),amount INTEGER NOT NULL CHECK(amount>=0),valid_from TEXT NOT NULL,valid_to TEXT, CHECK(valid_to IS NULL OR valid_to>=valid_from));
 CREATE TABLE IF NOT EXISTS costs(id INTEGER PRIMARY KEY,ticket_id INTEGER NOT NULL REFERENCES ticket_types(id),amount INTEGER NOT NULL CHECK(amount>=0),valid_from TEXT NOT NULL,valid_to TEXT,CHECK(valid_to IS NULL OR valid_to>=valid_from));
 CREATE TABLE IF NOT EXISTS bookings(id INTEGER PRIMARY KEY,code TEXT UNIQUE NOT NULL,book_date TEXT NOT NULL,agent_id INTEGER REFERENCES agents(id),customer_name TEXT DEFAULT '',ticket_id INTEGER NOT NULL REFERENCES ticket_types(id),ticket_name_snapshot TEXT NOT NULL,quantity INTEGER NOT NULL CHECK(quantity>0),sale_unit INTEGER NOT NULL CHECK(sale_unit>=0),cost_unit INTEGER NOT NULL CHECK(cost_unit>=0),created_by INTEGER NOT NULL REFERENCES users(id),created_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,booking_id INTEGER NOT NULL REFERENCES bookings(id),amount INTEGER NOT NULL CHECK(amount>0),paid_on TEXT NOT NULL,note TEXT DEFAULT '',created_by INTEGER NOT NULL REFERENCES users(id),created_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS supplier_payments(id INTEGER PRIMARY KEY,booking_id INTEGER NOT NULL REFERENCES bookings(id),amount INTEGER NOT NULL CHECK(amount>0),paid_on TEXT NOT NULL,created_by INTEGER NOT NULL REFERENCES users(id),created_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,user_id INTEGER,action TEXT NOT NULL,entity TEXT NOT NULL,entity_id TEXT,detail TEXT,at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS campaigns(id INTEGER PRIMARY KEY,title TEXT NOT NULL,body TEXT NOT NULL,created_by INTEGER REFERENCES users(id),created_at TEXT DEFAULT CURRENT_TIMESTAMP);
 CREATE TABLE IF NOT EXISTS campaign_recipients(id INTEGER PRIMARY KEY,campaign_id INTEGER NOT NULL REFERENCES campaigns(id),agent_id INTEGER NOT NULL REFERENCES agents(id),status TEXT NOT NULL DEFAULT 'pending',channel TEXT NOT NULL DEFAULT 'manual_zalo_pc',UNIQUE(campaign_id,agent_id));
 ''')
  c.commit()
init()

def hashpass(password,salt=None):
 salt=salt or secrets.token_hex(16)
 return salt+':'+hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),260000).hex()
def checkpass(password,stored):
 try:
  salt,expected=stored.split(':');return hmac.compare_digest(hashpass(password,salt),stored)
 except Exception:return False

def audit(c,user,action,entity,entity_id='',detail=''):
 c.execute('INSERT INTO audit(user_id,action,entity,entity_id,detail) VALUES(?,?,?,?,?)',(user,action,entity,str(entity_id),detail))

def auth(req,allowed=None):
 token=req.cookies.get('sunny_session','')
 if not token:raise HTTPException(401,'Vui lòng đăng nhập')
 with contextlib.closing(connect()) as c:
  u=c.execute('SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.tokenhash=? AND s.expires>? AND u.active=1',(hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()
 if not u:raise HTTPException(401,'Phiên đăng nhập hết hạn')
 user=dict(u)
 if allowed and user['role'] not in allowed:raise HTTPException(403,'Không có quyền')
 return user

def require_setup():
 with contextlib.closing(connect()) as c:return c.execute('SELECT COUNT(*) FROM users').fetchone()[0]==0

class Setup(BaseModel):
 username:str=Field(min_length=3,max_length=60)
 password:str=Field(min_length=12,max_length=256)
class Login(BaseModel):
 username:str;password:str
class Agent(BaseModel):
 code:str=Field(min_length=1,max_length=40);name:str=Field(min_length=1,max_length=200);phone:str='';active:bool=True;zalo_consent:bool=False
class Ticket(BaseModel):
 code:str=Field(min_length=1,max_length=40);name:str=Field(min_length=1,max_length=200)
class Booking(BaseModel):
 book_date:datetime.date;agent_id:int|None=None;customer_name:str='';ticket_id:int;quantity:int=Field(gt=0,le=10000);sale_unit:int|None=None;cost_unit:int|None=None
class Payment(BaseModel):
 amount:int=Field(gt=0);paid_on:datetime.date;note:str=''
class UserNew(BaseModel):
 username:str=Field(min_length=3,max_length=60);password:str=Field(min_length=12,max_length=256);role:str

@app.get('/')
def home():return FileResponse(ROOT/'static'/'index.html')
@app.get('/api/setup-status')
def status():return {'setup_required':require_setup()}
@app.post('/api/setup')
def setup(x:Setup):
 with contextlib.closing(connect()) as c:
  c.execute('BEGIN IMMEDIATE')
  if c.execute('SELECT COUNT(*) FROM users').fetchone()[0]:raise HTTPException(409,'Đã thiết lập quản trị viên')
  c.execute('INSERT INTO users(username,passhash,role) VALUES(?,?,?)',(x.username,hashpass(x.password),'admin'));c.commit()
 return {'ok':True}
@app.post('/api/login')
def login(x:Login,response:Response):
 with contextlib.closing(connect()) as c:
  u=c.execute('SELECT * FROM users WHERE username=? AND active=1',(x.username,)).fetchone()
  if not u or not checkpass(x.password,u['passhash']):raise HTTPException(401,'Sai tài khoản hoặc mật khẩu')
  token=secrets.token_urlsafe(48);c.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),u['id'],int(time.time())+8*3600));c.commit()
 response.set_cookie('sunny_session',token,httponly=True,secure=COOKIE_SECURE,samesite='strict',max_age=28800)
 return {'username':u['username'],'role':u['role']}
@app.post('/api/logout')
def logout(req:Request,response:Response):
 token=req.cookies.get('sunny_session','')
 with contextlib.closing(connect()) as c:c.execute('DELETE FROM sessions WHERE tokenhash=?',(hashlib.sha256(token.encode()).hexdigest(),));c.commit()
 response.delete_cookie('sunny_session');return {'ok':True}
@app.get('/api/me')
def me(req:Request):return auth(req)
@app.get('/api/agents')
def agents(req:Request):
 auth(req)
 with contextlib.closing(connect()) as c:return [dict(x) for x in c.execute('SELECT * FROM agents ORDER BY name')]
@app.post('/api/agents')
def add_agent(req:Request,x:Agent):
 u=auth(req,{'admin','manager'})
 try:
  with contextlib.closing(connect()) as c:
   cur=c.execute('INSERT INTO agents(code,name,phone,active,zalo_consent) VALUES(?,?,?,?,?)',(x.code,x.name,x.phone,int(x.active),int(x.zalo_consent)));audit(c,u['id'],'create','agent',cur.lastrowid);c.commit();return {'id':cur.lastrowid}
 except sqlite3.IntegrityError:raise HTTPException(409,'Mã đại lý đã tồn tại')
@app.get('/api/tickets')
def tickets(req:Request):
 auth(req)
 with contextlib.closing(connect()) as c:return [dict(x) for x in c.execute('SELECT * FROM ticket_types ORDER BY sort_order,id')]
@app.post('/api/tickets')
def add_ticket(req:Request,x:Ticket):
 u=auth(req,{'admin','manager'})
 try:
  with contextlib.closing(connect()) as c:
   cur=c.execute('INSERT INTO ticket_types(code,name) VALUES(?,?)',(x.code,x.name));audit(c,u['id'],'create','ticket',cur.lastrowid);c.commit();return {'id':cur.lastrowid}
 except sqlite3.IntegrityError:raise HTTPException(409,'Mã vé đã tồn tại')
@app.get('/api/bookings')
def bookings(req:Request):
 u=auth(req)
 with contextlib.closing(connect()) as c:
  rows=c.execute('''SELECT b.id,b.code,b.book_date,b.customer_name,b.ticket_name_snapshot,b.quantity,b.sale_unit,b.agent_id,a.name agent_name,b.created_at,COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.booking_id=b.id),0) received FROM bookings b LEFT JOIN agents a ON a.id=b.agent_id ORDER BY b.id DESC LIMIT 500''').fetchall()
  return [dict(r) for r in rows]
@app.post('/api/bookings')
def add_booking(req:Request,x:Booking):
 u=auth(req,{'admin','manager','seller'})
 with contextlib.closing(connect()) as c:
  c.execute('BEGIN IMMEDIATE')
  ticket=c.execute('SELECT name,active FROM ticket_types WHERE id=?',(x.ticket_id,)).fetchone()
  if not ticket or not ticket['active']:raise HTTPException(400,'Loại vé không hợp lệ')
  if x.agent_id is not None:
   a=c.execute('SELECT active FROM agents WHERE id=?',(x.agent_id,)).fetchone()
   if not a or not a['active']:raise HTTPException(400,'Đại lý không hoạt động')
  cost=c.execute('SELECT amount FROM costs WHERE ticket_id=? AND valid_from<=? AND COALESCE(valid_to,"9999-12-31")>=? ORDER BY valid_from DESC LIMIT 1',(x.ticket_id,str(x.book_date),str(x.book_date))).fetchone()
  if not cost:raise HTTPException(400,'Chưa khai báo giá vốn hợp lệ theo ngày')
  if x.agent_id is not None:
   price=c.execute('SELECT amount FROM prices WHERE ticket_id=? AND agent_id=? AND valid_from<=? AND COALESCE(valid_to,"9999-12-31")>=? ORDER BY valid_from DESC LIMIT 1',(x.ticket_id,x.agent_id,str(x.book_date),str(x.book_date))).fetchone()
   if not price:raise HTTPException(400,'Chưa khai báo giá bán đại lý hợp lệ theo ngày')
   sale=price['amount']
  else:
   if x.sale_unit is None:raise HTTPException(400,'Khách lẻ cần nhập giá bán')
   sale=x.sale_unit
  cur=c.execute('INSERT INTO bookings(code,book_date,agent_id,customer_name,ticket_id,ticket_name_snapshot,quantity,sale_unit,cost_unit,created_by) VALUES(?,?,?,?,?,?,?,?,?,?)',('TEMP-'+secrets.token_hex(12),str(x.book_date),x.agent_id,x.customer_name,x.ticket_id,ticket['name'],x.quantity,sale,cost['amount'],u['id']))
  code=f'ST-{x.book_date.strftime("%Y%m%d")}-{cur.lastrowid:06d}'
  c.execute('UPDATE bookings SET code=? WHERE id=?',(code,cur.lastrowid));audit(c,u['id'],'create','booking',cur.lastrowid);c.commit()
  return {'id':cur.lastrowid,'code':code}
@app.post('/api/bookings/{booking_id}/payments')
def add_payment(booking_id:int,req:Request,x:Payment):
 u=auth(req,{'admin','manager','accountant'})
 with contextlib.closing(connect()) as c:
  c.execute('BEGIN IMMEDIATE')
  b=c.execute('SELECT quantity,sale_unit FROM bookings WHERE id=?',(booking_id,)).fetchone()
  if not b:raise HTTPException(404,'Không tìm thấy booking')
  received=c.execute('SELECT COALESCE(SUM(amount),0) FROM payments WHERE booking_id=?',(booking_id,)).fetchone()[0]
  if received+x.amount>b['quantity']*b['sale_unit']:raise HTTPException(400,'Số tiền vượt công nợ')
  cur=c.execute('INSERT INTO payments(booking_id,amount,paid_on,note,created_by) VALUES(?,?,?,?,?)',(booking_id,x.amount,str(x.paid_on),x.note,u['id']));audit(c,u['id'],'create','payment',cur.lastrowid);c.commit();return {'id':cur.lastrowid}
@app.get('/api/dashboard')
def dashboard(req:Request):
 auth(req,{'admin','manager','accountant'})
 with contextlib.closing(connect()) as c:
  row=c.execute('''SELECT COALESCE(SUM(quantity*sale_unit),0) revenue,COALESCE(SUM(quantity*cost_unit),0) cost FROM bookings''').fetchone()
  paid=c.execute('SELECT COALESCE(SUM(amount),0) FROM payments').fetchone()[0]
  return {'revenue':row['revenue'],'cost':row['cost'],'received':paid,'receivable':row['revenue']-paid}
@app.get('/api/users')
def users(req:Request):
 auth(req,{'admin'})
 with contextlib.closing(connect()) as c:return [dict(x) for x in c.execute('SELECT id,username,role,active,created_at FROM users')]
@app.post('/api/users')
def add_user(req:Request,x:UserNew):
 u=auth(req,{'admin'})
 if x.role not in ROLES:raise HTTPException(400,'Vai trò không hợp lệ')
 try:
  with contextlib.closing(connect()) as c:
   cur=c.execute('INSERT INTO users(username,passhash,role) VALUES(?,?,?)',(x.username,hashpass(x.password),x.role));audit(c,u['id'],'create','user',cur.lastrowid);c.commit();return {'id':cur.lastrowid}
 except sqlite3.IntegrityError:raise HTTPException(409,'Tên đăng nhập đã tồn tại')
@app.get('/api/audit')
def audits(req:Request):
 auth(req,{'admin'})
 with contextlib.closing(connect()) as c:return [dict(x) for x in c.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 200')]
class Rate(BaseModel):
 ticket_id:int;agent_id:int|None=None;amount:int=Field(ge=0);valid_from:datetime.date;valid_to:datetime.date|None=None
@app.post('/api/costs')
def add_cost(req:Request,x:Rate):
 u=auth(req,{'admin','manager'})
 if x.valid_to and x.valid_to<x.valid_from:raise HTTPException(400,'Khoảng ngày không hợp lệ')
 with contextlib.closing(connect()) as c:
  overlaps=c.execute('SELECT id FROM costs WHERE ticket_id=? AND valid_from<=? AND COALESCE(valid_to,"9999-12-31")>=?',(x.ticket_id,str(x.valid_to or '9999-12-31'),str(x.valid_from))).fetchone()
  if overlaps:raise HTTPException(409,'Khoảng ngày giá vốn bị trùng')
  cur=c.execute('INSERT INTO costs(ticket_id,amount,valid_from,valid_to) VALUES(?,?,?,?)',(x.ticket_id,x.amount,str(x.valid_from),str(x.valid_to) if x.valid_to else None));audit(c,u['id'],'create','cost',cur.lastrowid);c.commit();return {'id':cur.lastrowid}
@app.post('/api/prices')
def add_price(req:Request,x:Rate):
 u=auth(req,{'admin','manager'})
 if not x.agent_id:raise HTTPException(400,'Cần chọn đại lý')
 if x.valid_to and x.valid_to<x.valid_from:raise HTTPException(400,'Khoảng ngày không hợp lệ')
 with contextlib.closing(connect()) as c:
  overlaps=c.execute('SELECT id FROM prices WHERE ticket_id=? AND agent_id=? AND valid_from<=? AND COALESCE(valid_to,"9999-12-31")>=?',(x.ticket_id,x.agent_id,str(x.valid_to or '9999-12-31'),str(x.valid_from))).fetchone()
  if overlaps:raise HTTPException(409,'Khoảng ngày giá bán bị trùng')
  cur=c.execute('INSERT INTO prices(ticket_id,agent_id,amount,valid_from,valid_to) VALUES(?,?,?,?,?)',(x.ticket_id,x.agent_id,x.amount,str(x.valid_from),str(x.valid_to) if x.valid_to else None));audit(c,u['id'],'create','price',cur.lastrowid);c.commit();return {'id':cur.lastrowid}
@app.get('/api/quote')
def quote(req:Request,ticket_id:int,book_date:datetime.date,agent_id:int|None=None):
 u=auth(req)
 with contextlib.closing(connect()) as c:
  cost=c.execute('SELECT amount FROM costs WHERE ticket_id=? AND valid_from<=? AND COALESCE(valid_to,"9999-12-31")>=? ORDER BY valid_from DESC LIMIT 1',(ticket_id,str(book_date),str(book_date))).fetchone()
  price=c.execute('SELECT amount FROM prices WHERE ticket_id=? AND agent_id=? AND valid_from<=? AND COALESCE(valid_to,"9999-12-31")>=? ORDER BY valid_from DESC LIMIT 1',(ticket_id,agent_id,str(book_date),str(book_date))).fetchone() if agent_id else None
  result={'sale_unit':price['amount'] if price else None,'has_cost':bool(cost)}
  if u['role']!='seller':result['cost_unit']=cost['amount'] if cost else None
  return result
