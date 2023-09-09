from fastapi import Request, FastAPI, status, Response, Cookie
import redis
import sqlite3
from hashlib import sha256, md5
from fastapi.responses import RedirectResponse
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse
from secrets import token_hex
from urllib.parse import unquote_plus
from cryptography.fernet import Fernet
import base64
import requests
import json

app = FastAPI()

def check_auth(token):
	if token == None:
		return False
	cur = redis.Redis(host='localhost', port=6379, db=0)
	if not cur.exists(token):
		return False
	cur = None
	return True


@app.get("/", response_class=HTMLResponse)
async def read_root():
	template = '''
		<!html>
			<head>
			</head>
			<body>
				<p>Чат 1.1</p>
				<form action="/auth" method="post">
					<p><input type="text" name="login"></p>
					<p><input type="text" name="password"></p>
					<p><input type="submit" value="Войти"></p>
				</form>
			</body>
		</html>
	'''
	return template


@app.post("/auth", response_class=HTMLResponse)
async def read_item(data: Request, response: Response):
	con = sqlite3.connect('users.db')
	cur = con.cursor()
	info_users = await data.body()
	info_users = dict(map(lambda x: x.split('='), info_users.decode('utf-8').split('&')))
	cur.execute("select * from users where name=? and password=?", (info_users['login'], sha256(str.encode(info_users['password'])).hexdigest()),)
	row = cur.fetchone()
	if row == None:
		return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
	cur.close()

	token = token_hex(16)
	response.set_cookie(key="token", value=token)
	cur = redis.Redis(host='localhost', port=6379, db=0)
	
	key = Fernet.generate_key()
	cur.set(token, key)
	timeout = 3600
	cur.expire(token, timeout)
	cur = None
	template = f'<p>Теперь вы {token}</p><a href="/{token}">Перейти в чат</a>'
	return template


@app.get("/{tmp_user_name}", response_class=HTMLResponse)
async def mess(token = Cookie(None)):
	if not check_auth(token):
		return 'Вам не рады'

	template = f'''
		<!html>
			<head>
				<style>
					section {{
						display: flex;
						flex-direction: row;
					}}

					article {{
				        padding: 10px;
				        margin: 10px;
				        background: grey;
				    }}

				    p {{
				    	word-wrap: break-word;
				    	overflow-x:hidden;
				    	color:white;
				    }}
				</style>
			</head>
			<body>	
				<section>
					<article>
						<p>Приветствуем {token}</p>
						<form action="/write_mess" method="post">
							<p><textarea name="w_mess_text" placeholder="Текст сообщения"></textarea></p>
							<p><textarea name="w_mess_token" placeholder="Токен сообщения"></textarea></p>
							<p><textarea name="w_mess_key" placeholder="Секретный ключ"></textarea></p>
							<p><textarea name="w_mess_ttl" placeholder="Время жизни сообщения (в секундах)"></textarea></p>
							<p><input type="submit" value="Написать личное сообщение"></p>
						</form>
						<form action="/read_mess" method="post">
							<p><textarea name="r_mess_token" placeholder="Токен сообщения"></textarea></p>
							<p><textarea name="r_mess_key" placeholder="Секретный ключ"></textarea></p>
							<p><input type="submit" value="Прочитать личное сообщение"></p>
						</form>
					</article>			
				</section>
			</body>
		</html>
	'''
	return template


@app.post("/write_mess")
async def registration(data: Request, token = Cookie(None)):
	if not check_auth(token):
		return 'Вам не рады'

	info_mess = await data.body()
	info_mess = dict(map(lambda x: x.split('='), info_mess.decode('utf-8').split('&')))

	cur = redis.Redis(host='localhost', port=6379, db=1)

	key = base64.urlsafe_b64encode(md5(info_mess['w_mess_key'].encode()).hexdigest().encode())
	crypt = Fernet(key)
	cur.set(info_mess['w_mess_token'], crypt.encrypt(str.encode(info_mess['w_mess_text'])))
	cur.expire(info_mess['w_mess_token'], int(info_mess['w_mess_ttl']))
	cur = None
	
	return RedirectResponse(url=f"/{token}", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/read_mess")
async def registration(data: Request, token = Cookie(None)):
	if not check_auth(token):
		return 'Вам не рады'

	info_mess = await data.body()
	info_mess = dict(map(lambda x: x.split('='), info_mess.decode('utf-8').split('&')))

	cur = redis.Redis(host='localhost', port=6379, db=1)
	mess = cur.get(info_mess['r_mess_token'])
	if mess == None:
		return "Кажется тут ничего нет"
	key = base64.urlsafe_b64encode(md5(info_mess['r_mess_key'].encode()).hexdigest().encode())
	crypt = Fernet(key)
	mess = crypt.decrypt(mess)
	mess = mess.decode('utf8')
	cur = None
	
	return unquote_plus(mess)


@app.get("/registration", response_class=HTMLResponse)
async def registration():
	template = '''
	<p>Регистрация<p>
	<form action="/insert_user" method="post">
		<p><input type="text" name="login"></p>
		<p><input type="text" name="password"></p>
		<p><input type="submit" value="Зарегестрировать"></p>
	</form>
	'''
	return template


@app.post("/insert_user")
async def registration(data: Request):
	con = sqlite3.connect('users.db')
	cur = con.cursor()
	info_users = await data.body()
	info_users = dict(map(lambda x: x.split('='), info_users.decode('utf-8').split('&')))
	salt = ""
	cur.execute("insert into users(name, password) values (?, ?)", (info_users['login'], sha256(str.encode(info_users['password']) + salt).hexdigest()),)
	con.commit()
	cur.close()
	return RedirectResponse(url="/registration", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/create_db/{db_name}")
async def registration(db_name):
	con = sqlite3.connect(db_name)
	cur = con.cursor()
	buff = '''
		CREATE TABLE IF NOT EXISTS users (
			name text NOT NULL,
			password text NOT NULL
		);
	'''
	cur.execute(buff)
	return cur.fetchone()