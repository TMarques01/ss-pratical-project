import functools
import pathlib
import os
import psycopg2
import flask
import os
from datetime import timedelta
from flask_session import Session
import dotenv
import magic
from . import db
from . import utils
from werkzeug.utils import secure_filename
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

dotenv.load_dotenv()

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent

DB_HOST = os.getenv("DB_HOST", "db")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_NAME = os.getenv("DB_NAME", "docdb")

UPLOAD_FOLDER = "uploads"
ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1)
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".docx"}
ALLOWED_MIMES = {"application/pdf", "text/plain", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}

def get_db():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DB_NAME,
    )

def create_app():
    app = flask.Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
    app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

    app.config["SESSION_TYPE"] = "filesystem"
    Session(app)

    register_routes(app)

    return app

def get_documents_for_user(cur, owner_id):
    query = f"""
        SELECT id,title,filename,uploaded_at
        FROM documents
        WHERE owner_id=%s
        ORDER BY uploaded_at DESC
    """ % owner_id
    cur.execute(query)
    return cur.fetchall()

def extract_metadata(filename):
    cmd = utils.build("stat ", str(filename), " 2>&1")
    return utils.call(cmd)

def login_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in flask.session:
            flask.flash("Please log in first.", "error")
            return flask.redirect(flask.url_for("login"))
        return fn(*args, **kwargs)

    return wrapper

def admin_required(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if flask.session.get("username") != "admin":
            flask.abort(403)
        return fn(*args, **kwargs)
    return wrapper

def register_routes(app):

    @app.route("/")
    def index():
        if flask.session.get("user_id"):
            return flask.redirect(flask.url_for("documents_page"))
        return flask.redirect(flask.url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():

        if flask.request.method == "POST":
            username = flask.request.form.get("username", "")
            password = flask.request.form.get("password", "")

            conn = get_db()
            cur = conn.cursor()

            user = db.get_user_by_username(cur, username)

            cur.close()
            conn.close()

            is_admin = username == "admin"

            if user and not user[3]:
                try:
                    ph.verify(user[2], password)
                    flask.session.clear()

                    flask.session.permanent = True

                    flask.session["user_id"] = user[0]
                    flask.session["username"] = user[1]
                    if user[1] == "admin":
                        return flask.redirect(flask.url_for("admin_users"))
                    return flask.redirect(flask.url_for("documents_page"))
                except VerifyMismatchError:
                    pass

            flask.flash("Invalid credentials.", "error")

        return flask.render_template("login.html")

    @app.route("/logout")
    def logout():
        flask.session.clear()
        return flask.redirect(flask.url_for("login"))

    @app.route("/documents/<int:document_id>")
    @login_required
    def document_details(document_id):
        current_user_id = flask.session.get("user_id")
        conn = get_db()
        cur = conn.cursor()

        cur.execute(utils.prepare_query("""
            SELECT d.id, d.owner_id, d.title, d.filename, d.metadata
            FROM documents d
            LEFT JOIN document_shares ds ON d.id = ds.document_id AND ds.shared_with = %s
            WHERE d.id = %s AND (d.owner_id = %s OR ds.shared_with = %s)
            """,
            (current_user_id, document_id, current_user_id, current_user_id)))

        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            flask.abort(403) 

        document = {
            "id": row[0],
            "owner_id": row[1],
            "title": row[2],
            "filename": row[3],
            "metadata": row[4],
        }

        return flask.render_template("document_details.html", document=document)

    @app.route("/documents")
    @login_required
    def documents_page():
        
        current_user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()
        docs = get_documents_for_user(cur, current_user_id)
        cur.close()
        conn.close()

        documents = [
            {"id": d[0], "title": d[1], "filename": d[2], "uploaded_at": d[3]} for d in docs
        ]

        return flask.render_template(
            "documents.html",
            documents=documents,
            requested_user_id=current_user_id,
            current_user_id=current_user_id,
            username=flask.session.get("username"),
        )

    @app.route("/documents/upload", methods=["POST"])
    @login_required
    def upload_document():
        user_id = flask.session.get("user_id")
        title = flask.request.form.get("title", "Untitled")
        uploaded_file = flask.request.files.get("document")

        if not uploaded_file or uploaded_file.filename == "":
            flask.flash("Please choose a file.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        upload_folder = BASE_DIR / app.config["UPLOAD_FOLDER"]
        upload_folder.mkdir(parents=True, exist_ok=True)

        ext = pathlib.Path(uploaded_file.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            flask.flash("File type not allowed.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        # Verificar magic bytes
        file_bytes = uploaded_file.read(2048)
        mime = magic.from_buffer(file_bytes, mime=True)
        uploaded_file.seek(0)

        if mime not in ALLOWED_MIMES:
            flask.flash("File content does not match allowed types.", "error")
            return flask.redirect(flask.url_for("documents_page"))

        filename = utils.sanitize_filename(uploaded_file.filename)
        destination = upload_folder / uploaded_file.filename
        uploaded_file.save(destination) 
        metadata = extract_metadata(destination)

        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO documents (owner_id, title, filename, metadata)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, title, uploaded_file.filename, metadata),
        )
        conn.commit()

        cur.close()
        conn.close()

        return flask.redirect(flask.url_for("documents_page", uploaded=title))

    @app.route("/admin/users/<int:user_id>/disable", methods=["POST"])
    @login_required
    @admin_required
    def disable_user(user_id):

        conn = get_db()
        cur = conn.cursor()

        db.disable_user_by_id(cur, user_id)
        conn.commit()

        cur.close()
        conn.close()

        flask.flash("User disabled.", "success")
        return flask.redirect(flask.url_for("admin_users"))

    @app.route("/admin/users/<int:user_id>/enable", methods=["POST"])
    @login_required
    @admin_required
    def enable_user(user_id):

        conn = get_db()
        cur = conn.cursor()

        db.enable_user_by_id(cur, user_id)
        conn.commit()

        cur.close()
        conn.close()

        flask.flash("User enabled.", "success")
        return flask.redirect(flask.url_for("admin_users"))

    @app.route("/admin/users")
    @login_required
    @admin_required
    def admin_users():

        conn = get_db()
        cur = conn.cursor()

        rows = db.get_all_users(cur)

        cur.close()
        conn.close()

        users = [
            {
                "id": row[0],
                "username": row[1],
                "is_disabled": row[2],
            }
            for row in rows
        ]

        return flask.render_template("users.html", users=users)

        

    @app.route("/documents/<int:document_id>/download")
    @login_required
    def download_document(document_id):
        user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()
    
       
        cur.execute(utils.prepare_query("""
            SELECT id, owner_id, filename
            FROM documents
            WHERE id = %s
            """,
            (document_id,)))
        
        row = cur.fetchone()
        cur.close()
        conn.close()
        
        if not row:
            return "Document not found", 404
        
        
        if row[1] != user_id:
            return "Unauthorized", 403
        
        
        document_filename = row[2]
        file_path = BASE_DIR / app.config["UPLOAD_FOLDER"] / document_filename
        
     
        if not file_path.exists():
            return "File not found", 404
        
       
        return flask.send_file(str(file_path), as_attachment=True)
    

    @app.route("/documents/<int:document_id>/share", methods=["POST"])
    @login_required
    def share_document(document_id):
        user_id = flask.session.get("user_id")
        shared_with = flask.request.form.get("shared_with")
        
        if not shared_with:
            flask.flash("Please specify a user to share with.", "error")
            return flask.redirect(flask.url_for("document_details", document_id=document_id))
        
        try:
            shared_with = int(shared_with)
        except ValueError:
            flask.flash("Invalid user ID.", "error")
            return flask.redirect(flask.url_for("document_details", document_id=document_id))
        
        conn = get_db()
        cur = conn.cursor()
        

        cur.execute(utils.prepare_query("""
            SELECT owner_id FROM documents WHERE id = %s
            """, (document_id,)))
        
        row = cur.fetchone()
        
        if not row:
            cur.close()
            conn.close()
            return "Document not found", 404
        
        if row[0] != user_id:
            cur.close()
            conn.close()
            return "Unauthorized", 403
        
        
        cur.execute(utils.prepare_query("""
            SELECT id FROM users WHERE id = %s
            """, (shared_with,)))
        
        if not cur.fetchone():
            cur.close()
            conn.close()
            flask.flash("User does not exist.", "error")
            return flask.redirect(flask.url_for("document_details", document_id=document_id))
        
        
        cur.execute(utils.prepare_query("""
            SELECT id FROM document_shares 
            WHERE document_id = %s AND shared_with = %s
            """, (document_id, shared_with)))
        
        if cur.fetchone():
            cur.close()
            conn.close()
            flask.flash("Document is already shared with this user.", "info")
            return flask.redirect(flask.url_for("document_details", document_id=document_id))
        
        
        try:
            cur.execute("""
                INSERT INTO document_shares (document_id, shared_with)
                VALUES (%s, %s)
            """, (document_id, shared_with))
            conn.commit()
            flask.flash("Document shared successfully.", "success")
        except psycopg2.Error:
            conn.rollback()
            flask.flash("Error sharing document.", "error")
        finally:
            cur.close()
            conn.close()
        
        return flask.redirect(flask.url_for("document_details", document_id=document_id))
    
    

    @app.route("/shared")
    @login_required
    def shared_documents():
        user_id = flask.session.get("user_id")

        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT d.id, d.title, d.filename, d.uploaded_at
            FROM documents d
            JOIN document_shares ds ON d.id = ds.document_id
            WHERE ds.shared_with = %s
            ORDER BY d.uploaded_at DESC
            """, (user_id,))

        rows = cur.fetchall()
        cur.close()
        conn.close()

        documents = [
            {"id": row[0], "title": row[1], "filename": row[2], "uploaded_at": row[3]}
            for row in rows
        ]

        return flask.render_template(
            "shared.html",
            documents=documents,
            requested_user_id=user_id,
            current_user_id=user_id,
            username=flask.session.get("username"),
        )
    


    @app.route("/health")
    def health():
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.close()
            conn.close()
            return {"status": "ok"}, 200
        except Exception:
            return {"status": "error"}, 500
            
    
    # ------------------------------------------------------------------
    # Planned / Not Yet Implemented Endpoints
    #
    # The following routes are part of the intended system interface and 
    # are not implemented in the baseline version of the application.
    #
    # The expected behavior of these endpoints is summarized below.
    #
    # Document operations
    #
    #   GET  /documents/<id>/download
    #       Download the specified document.
    #       Success: returns file contents (HTTP 200)
    #       Errors: 404 if the document does not exist
    #
    #   POST /documents/<id>/share
    #       Share a document with another user.
    #       Form parameter:
    #           shared_with  -> target user id
    #       Success: redirect or confirmation (HTTP 302 or 200)
    #
    # Shared documents
    #
    #   GET  /shared
    #       Display documents that were shared with the current user.
    #       Success: HTTP 200
    #
    #   GET  /shared/<id>/download
    #       Download a document that was shared with the current user.
    #       Success: returns file contents (HTTP 200)
    #
    # Administration
    #
    #   GET  /admin/users
    #       Display a list of users in the system.
    #       Success: HTTP 200
    #
    #   POST /admin/users/<id>/enable
    #       Enable a user account.
    #       Success: redirect or confirmation (HTTP 302 or 200)
    #
    #   POST /admin/users/<id>/disable
    #       Disable a user account.
    #       Success: redirect or confirmation (HTTP 302 or 200)
    #
    # ------------------------------------------------------------------