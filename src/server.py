import cgi
import datetime
from http.client import parse_headers
import http.server
import json
import os
import sqlite3
from urllib.parse import parse_qs
import http.cookies
import time
import uuid
from requests import session
import smtplib
from email.mime.text import MIMEText
SESSIONS = {}

class CustomHandler(http.server.BaseHTTPRequestHandler):
    # Initialisation de la base de données
    @staticmethod
    def init_database():
        conn = sqlite3.connect('../database/database.db')
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                name TEXT,
                surname TEXT,
                password TEXT,
                birth TEXT,
                email TEXT UNIQUE,  -- Assurez-vous que chaque e-mail est unique
                bio TEXT,
                isAdmin BOOLEAN,
                picture_path TEXT,
                isBlocked BOOLEAN
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER,
                created_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                post_id INTEGER PRIMARY KEY,
                user_id INTEGER,
                created_at TEXT,
                content TEXT,
                post_picture_path TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                from_id INTEGER,
                to_id INTEGER,
                created_at TEXT,
                content TEXT,
                FOREIGN KEY (from_id) REFERENCES users (id),
                FOREIGN KEY (to_id) REFERENCES users (id)
            )
        ''')
        

        conn.commit()
        conn.close()
            
    def is_authenticated(self) -> bool:
        if "Cookie" not in self.headers:
            return False

        try:
            cookie = http.cookies.SimpleCookie(self.headers["Cookie"])
            
            # Si le cookie "session_id" n'est pas présent, retournez False
            if "session_id" not in cookie:
                return False
            
            session_id = cookie["session_id"].value
            conn, cursor = self.connect_to_db()
            
            cursor.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
            session = cursor.fetchone()
            
            conn.close()

            if not session:
                return False
            
            current_time = float(time.time())
            expiration_time = float(session[2])  # Convertir l'heure d'expiration en float

            if current_time > expiration_time:
                return False
            else:
                return True

        except Exception as e:
            print(f"Exception encountered: {e}")
            return False



    # Connexion à la base de données et récupération du curseur
    def connect_to_db(self):
        conn = sqlite3.connect('../database/database.db')
        cursor = conn.cursor()
        return conn, cursor

    def handle_index(self):
        with open('index.html', 'r') as f:
            content = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(content.encode())
            
            
    # Gestion de l'inscription
    def handle_register(self, post_data):
        params = parse_qs(post_data)

        name = params['name'][0]
        surname = params['surname'][0]
        password = params['password'][0]
        birth = params['birth'][0]
        email = params['email'][0]
        bio = params['bio'][0]

        conn, cursor = self.connect_to_db()

        cursor.execute('INSERT INTO users (name, surname, password, birth, email, bio,isAdmin, isBlocked) VALUES (?, ?, ?, ?, ?, ?,?,?)',
                       (name, surname, password, birth, email, bio, 0, False))
        conn.commit()
        conn.close()

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Inscription ok')

    def handle_login(self, post_data):
        try:
            params = parse_qs(post_data)

            # Check if email and password are present in the post_data
            if 'email' not in params or 'password' not in params:
                raise ValueError("Missing email or password")

            email = params['email'][0]
            password = params['password'][0]

            conn, cursor = self.connect_to_db()

            cursor.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
            user = cursor.fetchone()

            # If user is None, then no user was found with the provided credentials
            if user is None:
                raise ValueError("Invalid credentials")

            user_id =  user[0]
            blocked_status = getBlockedStateById(user_id, self)

            if blocked_status == 1:
                # User is blocked
                raise ValueError("Blocked user")
            
            # Log the user in and redirect to a different page
            session_id = str(uuid.uuid4())
            cookie = http.cookies.SimpleCookie()
            cookie["session_id"] = session_id
            cursor.execute('INSERT INTO sessions (session_id, user_id, created_at) VALUES (?, ?, ?)',
                        (session_id, user[0], time.time() + 3600))
            conn.commit()
            conn.close()

            self.send_response(302)
            self.send_header('Location', '/profil.html')  # Redirect to the user profile page
            self.send_header("Set-Cookie", cookie["session_id"].OutputString())
            self.end_headers()

        except ValueError as e:
            self.send_response(400)  # Send a "Bad Request" status code
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            # Send a custom error message to the client
            error_message = f"<div style='color: red;'>{str(e)}</div>"
            self.wfile.write(error_message.encode('utf-8'))

    def handle_logout(self):
        if "Cookie" not in self.headers:
            return False
        cookie = http.cookies.SimpleCookie(self.headers["Cookie"])
        if "session_id" not in cookie:
            return False
        session_id = cookie["session_id"].value
        conn, cursor = self.connect_to_db()

        # Supprimer la session de la base de données
        cursor.execute("DELETE FROM sessions WHERE session_id=?", (session_id,))
        conn.commit()
        conn.close()

        self.send_response(302)
        # Si vous souhaitez également effacer le cookie côté client :
        expired_cookie = http.cookies.SimpleCookie()
        expired_cookie["session_id"] = ""
        expired_cookie["session_id"]["expires"] = 'Thu, 01 Jan 1970 00:00:00 GMT'  # Date dans le passé pour l'expirer
        self.send_header("Set-Cookie", expired_cookie["session_id"].OutputString())
        self.end_headers()
    
    # Gestion de recuperation mot passe
    def handle_forgetPassword(self, post_data):
        params = parse_qs(post_data)

        email = params['email'][0]
        print(email)
        conn, cursor = self.connect_to_db()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user is None:
            self.wfile.write(b'The user does not exist')
        else:
            self.wfile.write(b'E-mail sent!')
            return user
        
    # Recuperation User ID
    def handle_get_user_id(self, post_data):
        params = parse_qs(post_data)

        email = params['email'][0]
        print(email)
        conn, cursor = self.connect_to_db()

        cursor.execute("SELECT * FROM users WHERE email=?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user is None:
            self.wfile.write(b'The user does not exist')
        else:
            self.wfile.write(b'E-mail sent!')
            return user

    def get_user_id_from_cookie(self):
        cookie_string = self.headers.get('Cookie')
        if cookie_string:
            cookies = http.cookies.SimpleCookie()
            cookies.load(cookie_string)
            if 'session_id' in cookies:
                session_id = cookies['session_id'].value
                conn, cursor = self.connect_to_db()
                cursor.execute("SELECT user_id FROM sessions WHERE session_id=?", (session_id,))
                user = cursor.fetchone()
                conn.close()
                if user:
                    return user[0]
        return None


    


    def handle_upload_profile_picture(self):
            # Récupérez l'ID de l'utilisateur à partir du cookie
            user_id = self.get_user_id_from_cookie()
            if not user_id:
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Vous devez   pour  une image de profil.')
                return

            # Récupérez le fichier de la requête
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            file_item = form['profile_pic']

            # Vérifiez si le fichier a été téléchargé
            if file_item.filename:
                # Créez le dossier s'il n'existe pas
                if not os.path.exists('./profile_pics/'):
                    os.makedirs('./profile_pics/')

                # Écrivez le fichier dans le dossier
                with open(f'./profile_pics/{user_id}.jpg', 'wb') as f:
                    f.write(file_item.file.read())

                conn, cursor = self.connect_to_db()

                cursor.execute('UPDATE users SET picture_path = ? WHERE id = ?',
                            (f"./profile_pics/{user_id}.jpg", user_id))
                conn.commit()
                conn.close()
                
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Image de profil  avec !')
                
                

            else:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Aucun fichier n\'a  .')


    def handle_upload_post_picture(self):
            # Récupérez l'ID de l'utilisateur à partir du cookie
            user_id = self.get_user_id_from_cookie()
            
            print(user_id)
            if not user_id:
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Vous devez   pour  une image de profil.')
                return
            # Récupérez le fichier de la requête
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            file_item = form['posts_pics']

            # Vérifiez si le fichier a été téléchargé
            if file_item.filename:
                # Créez le dossier s'il n'existe pas
                if not os.path.exists('./posts_pics/'):
                    os.makedirs('./posts_pics/')

                # Écrivez le fichier dans le dossier
                with open(f'./posts_pics/{user_id}.jpg', 'wb') as f:
                    f.write(file_item.file.read())

                conn, cursor = self.connect_to_db()

                cursor.execute('UPDATE posts SET post_picture_path = ? WHERE id = ?',
                            (f"./posts_pics/{user_id}.jpg", user_id))
                conn.commit()
                conn.close()
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Image de profil  avec !')
            else:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Aucun fichier n\'a  .')

    def get_users_from_db(self):
        # Établissez une connexion à la base de données
        conn, cursor = self.connect_to_db()

        # Exécutez la requête SQL pour obtenir les données
        cursor.execute("SELECT id, name, surname FROM users")
        users = cursor.fetchall()

        # Fermez la connexion
        conn.close()

        # Convertissez les données en format JSON
        users_json = [{"id": user[0], "name": user[1], "surname": user[2]} for user in users]
        return users_json



    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
       
        if self.path == "/register":
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.handle_register(post_data)
        elif self.path == "/login":
            post_data = self.rfile.read(content_length).decode('utf-8')
            self.handle_login(post_data)
        elif self.path == "/forgetPassword":
            post_data = self.rfile.read(content_length).decode('utf-8')
            user_data = self.handle_forgetPassword(post_data)
            send_email('Password','You password is: '+user_data[3],user_data[5])
        elif self.path == "/private":
            post_data = self.rfile.read(content_length).decode('utf-8')

            if self.is_authenticated():
                self.send_response(302)
                self.send_header('Location', '/profil.html')
                self.end_headers()
            else:
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Session invalide ou non authentifiee.')

        elif self.path == "/setting":
            post_data = self.rfile.read(content_length).decode('utf-8')
            if self.is_authenticated():
                self.send_response(302)
                self.send_header('Location', '/setting.html')
                self.end_headers()

            else:
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Session invalide ou non authentifiee.')

        elif self.path == "/logout":
            self.handle_logout()    
        elif self.path == "/new_post":
            conn, cursor = self.connect_to_db()
            self.send_response(302)
            self.send_header('Location', '/profil.html')
            self.end_headers()
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            # Obtenez le contenu du post à partir de cgi.FieldStorage
            content = form.getvalue('text', '')  # Utilisez getvalue pour éviter les KeyErrors
            created_at = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            user_id = self.get_user_id_from_cookie()
            
            cursor.execute('INSERT INTO posts (user_id, created_at, content) VALUES (?, ?, ?)',
                        (user_id, created_at, content))
            post_id = cursor.lastrowid  # Récupérez l'ID du post que vous venez d'insérer
            urlPathPost = form.getvalue('urlPathPost', '')  # Utilisez getvalue pour éviter les KeyErrors
            print(urlPathPost)
            if(urlPathPost != None):
                cursor.execute('UPDATE posts SET post_picture_path = ? WHERE post_id = ?',
                                (urlPathPost, post_id))
            
             # Traitez le téléchargement de l'image
            file_item = form['posts_pics']
            if file_item.filename:
                if not os.path.exists('./posts_pics/'):
                    os.makedirs('./posts_pics/')
                with open(f'./posts_pics/{post_id}.jpg', 'wb') as f:
                    f.write(file_item.file.read())
                cursor.execute('UPDATE posts SET post_picture_path = ? WHERE post_id = ?',
                            (f"./posts_pics/{post_id}.jpg", post_id))
            conn.commit()
            conn.close()
        elif self.path == "/uploadProfilPicture":
            self.handle_upload_profile_picture()
            
        elif self.path == "/uploadProfilPictureUrl":
            user_id = self.get_user_id_from_cookie()
            post_data = self.rfile.read(content_length).decode('utf-8')
            # Étape 1: Parsez post_data pour obtenir le contenu du post
            params = parse_qs(post_data)
            url_path = params['urlPath'][0] 
            conn, cursor = self.connect_to_db()

            cursor.execute('UPDATE users SET picture_path = ? WHERE id = ?',
                        (url_path, user_id))
            conn.commit()
            conn.close()
            
            self.send_response(302)
            self.send_header('Location', '/profil.html')  # Redirect to the user profile page
            #self.send_header("Set-Cookie", cookie["session_id"].OutputString())
            self.end_headers()
        elif self.path == "/update_settings":
            if not self.is_authenticated():
                # Redirigez vers la page de connexion si l'utilisateur n'est pas authentifié
                self.send_response(302)
                self.send_header('Location', '/login.html')  # Remplacez par l'URL de la page de connexion
                self.end_headers()
            else:
                if self.command == 'POST':
                    # Traitement des données POST pour la mise à jour
                    content_length = int(self.headers['Content-Length'])
                    post_data = self.rfile.read(content_length).decode('utf-8')
                    parsed_data = parse_qs(post_data)

                    user_id = self.get_user_id_from_cookie()
                    new_name = parsed_data['name'][0]
                    new_surname = parsed_data['surname'][0]
                    new_bio = parsed_data['bio'][0]
                    new_password = parsed_data['password'][0]
                    new_email = parsed_data['email'][0]

                    # Mettez à jour les données de l'utilisateur dans la base de données
                    conn, cursor = self.connect_to_db()
                    cursor.execute("UPDATE users SET name=?, surname=?, bio=?, email=?,password=? WHERE id=?", (new_name, new_surname, new_bio,new_email,new_password, user_id))
                    conn.commit()
                    conn.close()

                    # Redirigez l'utilisateur vers la page de paramètres mise à jour ou ailleurs
                    self.send_response(302)
                    self.send_header('Location', '/setting.html')  # Redirigez l'utilisateur vers la page de paramètres mise à jour
                    self.end_headers()
        elif self.path == "/administration":
            if self.is_authenticated():
                # Récupérez les données des utilisateurs depuis la base de données
                conn, cursor = self.connect_to_db()
                cursor.execute("SELECT * FROM users")
                users_data = cursor.fetchall()
                conn.close()

                # Générez le contenu HTML de la table en utilisant les données des utilisateurs
                table_content = ""
                for user in users_data:
                    user_id, user_name, user_surname, user_password, user_birth, user_email, user_bio, user_isAdmin, picturePath, is_blocked = user
                    
                    print("admin = "+ str(user_isAdmin) + " - isBlocked = "+ str(is_blocked))
                    table_content += f"<tr>"
                    table_content += f"<td>{user_id}</td>"
                    table_content += f"<td><input type='text' id='name_{user_id}' value='{user_name}'></td>"
                    table_content += f"<td><input type='text' id='surname_{user_id}' value='{user_surname}'></td>"
                    table_content += f"<td><input type='text' id='password_{user_id}' value='{user_password}'></td>"
                    table_content += f"<td><input type='text' id='birth_{user_id}' value='{user_birth}'></td>"
                    table_content += f"<td><input type='text' id='email_{user_id}' value='{user_email}'></td>"
                    table_content += f"<td><input type='text' id='bio_{user_id}' value='{user_bio}'></td>"
                    table_content += f"<td><input type='radio' id='isAdmin_true_{user_id}' name='isAdmin_{user_id}' value={1} {'checked' if user_isAdmin == 1 else ''}>True"
                    table_content += f"<input type='radio' id='isAdmin_false_{user_id}' name='isAdmin_{user_id}' value={0} {'checked' if user_isAdmin == 0 else ''}>False</td>"
                    table_content += f"<td><input type='radio' id='isBlocked_true_{user_id}' name='isBlocked_{user_id}' value={1} {'checked' if is_blocked == 1 else ''}>True"
                    table_content += f"<input type='radio' id='isBlocked_false_{user_id}' name='isBlocked_{user_id}' value={0} {'checked' if is_blocked == 0 else ''}>False</td>"
                    table_content += f"<td><button onclick='updateUser({user_id})'>Update</button></td>"
                    table_content += f"<td><button onclick='deleteUser({user_id})'>Delete</button></td>"

                    table_content += f"</tr>"


                user_id = self.get_user_id_from_cookie()
                adminStatus = getAdminStateById(user_id, self)

                if adminStatus == 1:
                    # Chargez le contenu du fichier 'administration.html'
                    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'administration.html'), 'r') as file:
                        admin_template = file.read()
                        
                    # Remplacez les placeholders par le contenu généré
                    admin_page = admin_template.replace('{table_content}', table_content)
                else:
                    admin_page = """ <p>not admin no panel</p>"""

                # Envoie la page au client
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(admin_page.encode('utf-8'))

            else:
                self.send_response(403)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Access denied. Authentication required.')
                
                
        elif self.path == "/administration-update":
            if self.is_authenticated():
                # Obtenez les données JSON de la requête POST
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length).decode('utf-8')
                user_data = json.loads(post_data)

                # Récupérez les valeurs des champs
                user_id = user_data['userId']
                name = user_data['name']
                surname = user_data['surname']
                password = user_data['password']
                birth = user_data['birth']
                email = user_data['email']
                bio = user_data['bio']
                isAdmin = user_data['isAdmin']
                isBlocked = user_data['isBlocked']

                # Mettez à jour les informations de l'utilisateur dans la base de données
                conn, cursor = self.connect_to_db()
                cursor.execute("UPDATE users SET name=?, surname=?, password=?, birth=?, email=?, bio=?, isAdmin=?, isBlocked=? WHERE id=?",
                            (name, surname, password, birth, email, bio, isAdmin, isBlocked, user_id))
                conn.commit()
                conn.close()

                # Répondez avec un code de réussite (200 OK)
                self.send_response(200)
                self.end_headers()
            else:
                # Si l'utilisateur n'est pas authentifié, répondez avec un code d'erreur (403 Forbidden)
                self.send_response(403)
                self.end_headers()


    def do_DELETE(self):
        if self.path.startswith("/delete-user/"):
            user_id = int(self.path.split("/")[-1])

            try:
                # Établir une connexion à la base de données SQLite3
                conn, cursor = self.connect_to_db()

                # Exécutez une commande SQL pour supprimer l'utilisateur en fonction de son ID
                cursor.execute("DELETE FROM users WHERE id=?", (user_id,))

                # Validez et enregistrez les modifications dans la base de données
                conn.commit()

                # Fermez la connexion à la base de données
                conn.close()

                # Répondez avec un code de réponse HTTP 200 pour indiquer que la suppression a réussi
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write("User deleted".encode('utf-8'))
            except Exception as e:
                # En cas d'erreur lors de la suppression, renvoyez un code de réponse HTTP 500 et affichez l'erreur
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                error_message = f"Error deleting user: {str(e)}"
                self.wfile.write(error_message.encode('utf-8'))
                # Affichez l'erreur dans la console pour le débogage
                print(error_message)
        else:
            # Gérez d'autres demandes DELETE ici si nécessaire
            self.send_response(501)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write("Unsupported DELETE request".encode('utf-8'))

    def do_GET(self):
        if self.path == "/profil.html":
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            user_id = self.get_user_id_from_cookie()
            conn, cursor = self.connect_to_db()
            cursor.execute("SELECT name, surname, bio FROM users WHERE id=?", (user_id,))
            user = cursor.fetchone()
            cursor.execute("SELECT * FROM posts WHERE user_id=?", (user_id,))
            posts = cursor.fetchall()    

            
            conn.close()
            if user:
                user_name = user[0]
                user_surname = user[1]
                user_bio = user[2]
                self.wfile.write(user_name.encode() + b" " +user_surname.encode() + b"<br/>Bio :<br/>" +user_bio.encode()+b"<br/><br/><br/><br/><br/>")
                picture_path = get_profil_picture_from_user_id(self,user_id)
                if(picture_path[0] != None):
                    htmlProfilPicture_content = "<img  style='width:10%' src='"+picture_path[0]+"' alt='image de profil'/>"
                    self.wfile.write(htmlProfilPicture_content.encode())
            with open("profil.html", "r") as file:
                self.wfile.write(file.read().encode())
            for post in posts:
                self.wfile.write(b'<div class="post">')  # Début d'une publication
                self.wfile.write(f'<p class="post-content">{post[2]}<br/>{post[3]}</p>'.encode())  # Contenu du post

                if post[4]:  # S'il y a un chemin d'image de post
                    self.wfile.write(f'<img src="{post[4]}" class="post-image">'.encode())  # Image du post

                self.wfile.write(b'</div>')  # Fin de la publication
                self.wfile.write(b'<hr>')  # Ligne de séparation entre les publications
        
        elif self.path == "/login":
            form_html = "t'es bete"
            self.wfile.write(form_html.encode())

            
        elif self.path == "/setting.html":
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            user_id = self.get_user_id_from_cookie()
            conn, cursor = self.connect_to_db()
            cursor.execute("SELECT name, surname, bio, password, email FROM users WHERE id=?", (user_id,))
            user = cursor.fetchone()
            conn.close()

            if user:
                user_name = user[0]
                user_surname = user[1]
                user_bio = user[2]
                user_password = user[3]
                user_email = user[4]

                # Lisez le contenu du fichier HTML
                file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'setting.html')
                with open(file_path, 'r') as f:

                    form_template = f.read()

                # Remplacez les placeholders par les valeurs dynamiques
                form_html = form_template.replace("%%USER_NAME%%", user_name)
                form_html = form_html.replace("%%USER_SURNAME%%", user_surname)
                form_html = form_html.replace("%%USER_BIO%%", user_bio)
                form_html = form_html.replace("%%USER_PASSWORD%%", user_password)
                form_html = form_html.replace("%%USER_EMAIL%%", user_email)

                self.wfile.write(form_html.encode())


        elif self.path.startswith("/profile_pics/"):
            # Construire le chemin complet vers l'image
            file_path = self.path[1:]  # remove the leading '/'
            
            try:
                # Ouvrir et lire l'image
                with open(file_path, 'rb') as f:
                    # Envoyer une réponse HTTP 200 (OK)
                    self.send_response(200)
                    # Définir le type MIME de la réponse comme image JPEG
                    self.send_header('Content-type', 'image/jpeg')
                    self.end_headers()
                    # Écrire le contenu de l'image dans la réponse
                    self.wfile.write(f.read())
            except FileNotFoundError:
                # Si l'image n'est pas trouvée, renvoyer une erreur 404
                self.send_response(404)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Image not found')
        elif self.path.startswith("/posts_pics/"):
            # Construire le chemin complet vers l'image
            file_path = self.path[1:]  # remove the leading '/'
            
            try:
                # Ouvrir et lire l'image
                with open(file_path, 'rb') as f:
                    # Envoyer une réponse HTTP 200 (OK)
                    self.send_response(200)
                    # Définir le type MIME de la réponse comme image JPEG
                    self.send_header('Content-type', 'image/jpeg')
                    self.end_headers()
                    # Écrire le contenu de l'image dans la réponse
                    self.wfile.write(f.read())
            except FileNotFoundError:
                # Si l'image n'est pas trouvée, renvoyer une erreur 404
                self.send_response(404)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(b'Image not found')
        elif self.path == '/users':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            users = self.get_users_from_db()
            response_content = json.dumps(users).encode()
            print(response_content)
            self.wfile.write(response_content)
            
        elif self.path.startswith('/user/'):
            user_id = self.path.split('/')[2]  # Récupère l'ID de l'utilisateur après '/user/'
            user_info, user_posts = get_user_info(self, user_id)

            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()

            # Affichez les informations de l'utilisateur
            response = f"Name: {user_info[0]}<br>"
            response += f"Surname: {user_info[1]}<br>"
            response += f"Bio: {user_info[2]}<br>"
            
            # Vérifiez si le chemin de l'image de l'utilisateur est None
            if user_info[3]:
                formatted_image_src = format_image_src(user_info[3])
                response += f"Picture: <img src='{formatted_image_src}'><br>"
            else:
                response += "No profile picture available.<br>"

            # Affichez les posts de l'utilisateur
            for post in user_posts:
                response += f"Content: {post[0]}<br>"
                response += f"Timestamp: {post[1]}<br>"
                
                # Vérifiez si le chemin de l'image du post est None
                if post[2]:
                    formatted_post_image_src = format_image_src(post[2])
                    response += f"Picture: <img src='{formatted_post_image_src}'><br><br>"
                else:
                    response += "No post picture available.<br><br>"
            response += '''
                    <form action="http://localhost:8001/message" method="post">
                        <label for="sendMessage">Send Message</label>
                        <textarea id="private_message" name="private_message"></textarea>
                        <input type="hidden" name="user_id" value="{user_id}">
                        <input type="submit" value="Send">
                    </form>
                    '''
            self.wfile.write(response.encode())

        elif self.path.startswith("/delete-user/"):
            # Récupérez l'ID de l'utilisateur à partir de l'URL
            user_id = int(self.path.split("/")[-1])

            try:
                conn, cursor = self.connect_to_db()
                cursor.execute("DELETE FROM users WHERE user_id=?", (user_id,))
                conn.commit()
                conn.close()
                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write("User deleted".encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(f"Error deleting user: {str(e)}".encode('utf-8'))
        else:
            print("else")

def get_user_info_from_database(user_id,self):
    
    conn, cursor = self.connect_to_db()

    cursor.execute("SELECT name, surname, email, bio FROM users WHERE id=?", (user_id,))
    user_info = cursor.fetchone()
    conn.close()
    return user_info


def format_image_src(image_path):
    """Retourne le chemin formaté pour l'image."""
    if image_path.startswith(('http://', 'https://')):
        return image_path  # URL externe
    else:
        return f"http://localhost:8001/{image_path}"  # Chemin vers une image sur votre serveur
    
def get_user_info(self, user_id):
    conn, cursor = self.connect_to_db()
    cursor.execute("SELECT name, surname, bio, picture_path, id FROM users WHERE id=?", (user_id,))
    user_info = cursor.fetchone()
    cursor.execute("SELECT content, created_at, post_picture_path FROM posts WHERE user_id=?", (user_id,))
    user_posts = cursor.fetchall()
    conn.close()
    return user_info, user_posts
    
def get_profil_picture_from_user_id(self,user_id):
    conn, cursor = self.connect_to_db()
    cursor.execute("SELECT picture_path FROM users WHERE id=?", (user_id,))
    picture_path = cursor.fetchone()
    conn.close()
    return picture_path 

def send_email(subject, body, to_email):
    # Vos identifiants
    gmail_user = 'y.qwerty1900@gmail.com'
    gmail_password = 'wcddlamqvowznenh'

    # Création du message
    msg = MIMEText(body)
    msg['From'] = gmail_user
    msg['To'] = to_email
    msg['Subject'] = subject

    try:
        # Connexion au serveur et envoi de l'email
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(gmail_user, gmail_password)
        server.sendmail(gmail_user, to_email, msg.as_string())
        server.close()
        print('Email envoyé !')
    except Exception as e:
        print('Erreur:', e)
        
def getAdminStateById(user_id,self):
    # Établissez la connexion à la base de données
    conn, cursor = self.connect_to_db()
    
    # Exécutez une requête SQL pour récupérer l'état d'administrateur de l'utilisateur
    cursor.execute("SELECT isAdmin FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()

    if result:
        # Si un résultat est trouvé, retournez la valeur d'isAdmin
        is_admin = result[0]
        conn.close()
        return is_admin
    else:
        # Si aucun résultat n'est trouvé, retournez une valeur par défaut (par exemple, False)
        conn.close()
        return False


def getBlockedStateById(user_id,self):
    # Établissez la connexion à la base de données
    conn, cursor = self.connect_to_db()
    
    # Exécutez une requête SQL pour récupérer l'état d'administrateur de l'utilisateur
    cursor.execute("SELECT isBlocked FROM users WHERE id = ?", (user_id,))
    result = cursor.fetchone()
    if result:
        # Si un résultat est trouvé, retournez la valeur d'isAdmin
        is_admin = result[0]
        conn.close()
        return is_admin
    else:
        # Si aucun résultat n'est trouvé, retournez une valeur par défaut (par exemple, False)
        conn.close()
        return False

def admin_or_user(isAdmin,self):
    if isAdmin == True:
        self.wfile.write(b'User Admin')
    else:
        self.wfile.write(b'User Client')
                    
# Initialisation et démarrage du serveur
def run_server():
    CustomHandler.init_database()
    server_address = ('', 8001)
    httpd = http.server.HTTPServer(server_address, CustomHandler)

    print('Serveur démarré...')
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()

