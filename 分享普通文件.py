import os
import random
import sqlite3
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    abort, send_from_directory, jsonify, g
)
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, \
    current_user, login_required
from werkzeug.utils import secure_filename
from mimetypes import guess_type

app = Flask(__name__)
app.secret_key = "your_secret_key_here_change_me"  # 必须设置安全密钥

bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

STORAGE_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "storage")
os.makedirs(STORAGE_ROOT, exist_ok=True)  # 确保存储目录存在

DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), "users.db")

class User(UserMixin):
    def __init__(self, id:int, username:str, password_hash:str, sharing_enabled:bool):
        self.id = str(id)
        self.username = username
        self.password_hash = password_hash
        self.sharing_enabled = sharing_enabled

    def get_id(self):
        return self.id

defdef get_db():
    # 从Flask的g对象获取当前请求的数据库连接，如果没有则创建一个新的SQLite连接
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)  # 连接到指定数据库文件
        db.row_factory = sqlite3.Row  # 设置返回结果为字典风格，可用列名访问字段
    return db  # 返回数据库连接对象

@app.teardown_appcontext
def close_connection(exception):
    # 当Flask请求上下文结束时调用，关闭数据库连接释放资源
    db = getattr(g, '_database', None)  # 获取存储的连接
    if db is not None:
        db.close()  # 关闭数据库连接

def init_db():
    # 初始化数据库，创建用户表（如果还未存在）
    db = get_db()
    db.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,  -- 用户唯一自增ID
        username TEXT UNIQUE NOT NULL,          -- 用户名，唯一且不能为空
        password_hash TEXT NOT NULL,            -- 密码哈希值
        sharing_enabled INTEGER NOT NULL DEFAULT 0  -- 共享开关，0关闭，1开启，默认0
    )
    ''')
    db.commit()  # 提交事务保存表结构



def get_user_by_username(username):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    return user

def create_user(username, password_hash):
    db = get_db()
    db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
    db.commit()

def update_sharing_enabled(username, enabled: bool):
    db = get_db()
    db.execute("UPDATE users SET sharing_enabled = ? WHERE username = ?", (1 if enabled else 0, username))
    db.commit()

def update_password(username, new_password_hash):
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_password_hash, username))
    db.commit()

@login_manager.user_loader
def load_user(user_id:str):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row:
        return User(row["id"], row["username"], row["password_hash"], bool(row["sharing_enabled"]))
    return None

def get_user_storage(username:str) -> str:
    path = os.path.join(STORAGE_ROOT, username)
    os.makedirs(path, exist_ok=True)  # 每个用户单独目录
    return path

def secure_path(base:str, *paths) -> str:
    new_path = os.path.abspath(os.path.join(base, *paths))
    base = os.path.abspath(base)
    if not new_path.startswith(base):
        raise Exception("Path traversal detected!")
    return new_path

def build_breadcrumb(path:str):
    parts = path.strip("/").split("/") if path else []
    result = [("Root", url_for("browse_all"))]
    cum_path = ""
    for part in parts:
        cum_path = cum_path + "/" + part if cum_path else part
        result.append((part, url_for("browse_all", path=cum_path)))
    return result

@app.route("/")
def home():
    return render_template("home.html", user=current_user)

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password cannot be empty.", "danger")
            return redirect(url_for("register"))
        if get_user_by_username(username):
            flash("Username already exists.", "warning")
            return redirect(url_for("register"))
        password_hash = bcrypt.generate_password_hash(password).decode()  # 密码哈希
        create_user(username, password_hash)  # 写入数据库
        get_user_storage(username)  # 创建用户存储目录
        flash("Registration successful. Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user_row = get_user_by_username(username)
        if not user_row:
            flash("User not found.", "danger")
            return redirect(url_for("login"))
        if not bcrypt.check_password_hash(user_row["password_hash"], password):  # 密码验证
            flash("Wrong password.", "danger")
            return redirect(url_for("login"))
        user = User(user_row["id"], user_row["username"], user_row["password_hash"], bool(user_row["sharing_enabled"]))
        login_user(user)
        flash("Login successful.", "success")
        return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout_post():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for("home"))

@app.route("/myfiles/", defaults={"path": ""})
@app.route("/myfiles/<path:path>")
@login_required
def myfiles(path):
    base = get_user_storage(current_user.username)  # 获取当前用户存储根目录路径
    try:
        abs_path = secure_path(base, path)  # 拼接并校验路径，防止目录穿越攻击
    except:
        abort(403)  # 拒绝非法访问
    if not os.path.exists(abs_path):
        abort(404)  # 路径不存在返回404
    if os.path.isfile(abs_path):
        dir_name, filename = os.path.split(abs_path)  # 拆分文件路径和文件名
        return send_from_directory(dir_name, filename, as_attachment=True)  # 文件下载响应
    dirs = []
    files = []
    for f in os.listdir(abs_path):  # 遍历当前目录内容
        full_f = os.path.join(abs_path, f)
        if os.path.isdir(full_f):
            dirs.append(f)  # 收集文件夹名列表
        else:
            files.append(f)  # 收集文件名列表
    breadcrumb = build_breadcrumb(path)  # 构建面包屑导航列表
    return render_template("myfiles.html",  # 渲染模板，传入变量
                           dirs=sorted(dirs),  # 排序后的子文件夹列表
                           files=sorted(files),  # 排序后的文件列表
                           current_path=path,  # 当前路径
                           breadcrumb=breadcrumb,  # 面包屑导航数据
                           user=current_user)  # 当前登录用户对象

@app.route("/myfiles/create_folder", methods=["POST"])
@login_required
def create_folder():
    folder_name = request.form.get("folder_name", "").strip()
    parent_path = request.form.get("current_path", "")
    if not folder_name:
        flash("Folder name cannot be empty.", "danger")
        return redirect(url_for("myfiles", path=parent_path))
    folder_name = secure_filename(folder_name)
    base = get_user_storage(current_user.username)
    try:
        abs_parent = secure_path(base, parent_path)
    except:
        abort(403)
    new_folder = os.path.join(abs_parent, folder_name)
    if os.path.exists(new_folder):
        flash("Folder exists.", "warning")
    else:
        os.makedirs(new_folder)
        flash("Folder created.", "success")
    return redirect(url_for("myfiles", path=parent_path))

@app.route("/myfiles/upload_file", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return jsonify({"error":"No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400
    parent_path = request.form.get("current_path", "")
    base = get_user_storage(current_user.username)
    try:
        abs_parent = secure_path(base, parent_path)
    except:
        return jsonify({"error": "Forbidden"}), 403
    filename = secure_filename(file.filename)
    save_path = os.path.join(abs_parent, filename)
    file.save(save_path)  # 保存上传文件
    return jsonify({"success": True, "filename": filename})

@app.route("/myfiles/toggle_sharing", methods=["POST"])
@login_required
def toggle_sharing():
    new_status = not current_user.sharing_enabled
    update_sharing_enabled(current_user.username, new_status)  # 更新数据库共享状态
    flash(f"Sharing has been {'enabled' if new_status else 'disabled'}.", "info")
    return redirect(url_for("myfiles"))

@app.route("/myfiles/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")
        user_row = get_user_by_username(current_user.username)
        if not bcrypt.check_password_hash(user_row["password_hash"], current_pw):
            flash("Current password is incorrect.", "danger")
            return redirect(url_for("change_password"))
        if new_pw != confirm_pw:
            flash("New password and confirmation do not match.", "danger")
            return redirect(url_for("change_password"))
        if len(new_pw) < 6:
            flash("New password should be at least 6 characters.", "danger")
            return redirect(url_for("change_password"))
        new_hash = bcrypt.generate_password_hash(new_pw).decode()
        update_password(current_user.username, new_hash)  # 更新数据库密码哈希
        flash("Password changed successfully.", "success")
        return redirect(url_for("myfiles"))
    return render_template("change_password.html", user=current_user)

@app.route("/browse/", defaults={"path": ""})
@app.route("/browse/<path:path>")
def browse_all(path):
    abs_root = STORAGE_ROOT  # 文件存储根目录路径
    try:
        abs_path = secure_path(abs_root, path)  # 组合请求路径并安全校验，防目录穿越攻击
    except:
        abort(403)  # 非法路径访问拒绝
    if not os.path.exists(abs_path):
        abort(404)  # 路径不存在返回404
    if os.path.isfile(abs_path):
        dir_name, filename = os.path.split(abs_path)  # 分离文件目录和文件名
        return send_from_directory(dir_name, filename, as_attachment=False)  # 直接内嵌播放文件
    dirs = []
    files = []
    for e in os.listdir(abs_path):  # 遍历目录下所有条目
        full_e = os.path.join(abs_path, e)  # 条目完整路径
        rel_path_parts = os.path.relpath(full_e, STORAGE_ROOT).split(os.sep)  # 相对存储根目录的路径部分
        if len(rel_path_parts) == 1:
            username = rel_path_parts[0]  # 顶级目录即为用户名
            user_row = get_user_by_username(username)  # 查询用户数据
            if not user_row or not user_row["sharing_enabled"]:
                continue  # 跳过未开启共享的用户目录，不显示
        if os.path.isdir(full_e):
            dirs.append(e)  # 目录列表
        else:
            files.append(e)  # 文件列表
    breadcrumb = build_breadcrumb(path)  # 构造面包屑导航数据
    return render_template("browse.html",  # 渲染浏览页面模板
                           dirs=sorted(dirs),  # 排序后的目录列表
                           files=sorted(files),  # 排序后的文件列表
                           breadcrumb=breadcrumb,  # 面包屑导航数据
                           current_path=path)  # 当前浏览路径





@app.route("/browse_random")
def browse_random():
    db = get_db()
    users_with_sharing = db.execute("SELECT username FROM users WHERE sharing_enabled=1").fetchall()
    shared_users = [u["username"] for u in users_with_sharing]
    if not shared_users:
        flash("No shared files available.", "info")
        return redirect(url_for("home"))
    for _ in range(10):
        user = random.choice(shared_users)
        user_dir = get_user_storage(user)
        all_entries = []
        for root, dirs, files_ in os.walk(user_dir):
            for d in dirs:
                rel = os.path.relpath(os.path.join(root, d), STORAGE_ROOT)
                all_entries.append(("dir", rel))
            for f in files_:
                rel = os.path.relpath(os.path.join(root, f), STORAGE_ROOT)
                all_entries.append(("file", rel))
        if all_entries:
            etype, rel_path = random.choice(all_entries)
            if etype == "file":
                filename = os.path.basename(rel_path)
                return render_template("browse_random_file.html",
                                       filename=filename,
                                       rel_path=rel_path,
                                       user_folder=user)
            else:
                abs_path = os.path.join(STORAGE_ROOT, rel_path)
                folders = []
                files_ = []
                for ent in os.listdir(abs_path):
                    if os.path.isdir(os.path.join(abs_path, ent)):
                        folders.append(ent)
                    else:
                        files_.append(ent)
                breadcrumb = build_breadcrumb(rel_path)
                return render_template("browse_random_dir.html",
                                       dirs=sorted(folders),
                                       files=sorted(files_),
                                       breadcrumb=breadcrumb,
                                       user_folder=user,
                                       rel_path=rel_path)
    flash("No files available for browsing.", "info")
    return redirect(url_for("home"))

@app.route("/shared/<path:path>")
def serve_shared(path):
    safe_path = os.path.abspath(os.path.join(STORAGE_ROOT, path))
    if not safe_path.startswith(STORAGE_ROOT):
        abort(403)
    if not os.path.isfile(safe_path):
        abort(404)
    dir_name, fname = os.path.split(safe_path)
    return send_from_directory(dir_name, fname, as_attachment=False)  # 内嵌提供文件

@app.route("/search")
def search_files():
    keyword = request.args.get("q", "").lower()
    if not keyword:
        flash("Please provide search keyword", "warning")
        return redirect(url_for("home"))

    db = get_db()
    results = []
    rows = db.execute("SELECT username FROM users WHERE sharing_enabled=1").fetchall()
    shared_users = [r["username"] for r in rows]

    for username in shared_users:
        user_path = get_user_storage(username)
        for root, dirs, files_ in os.walk(user_path):
            for f in files_:
                if keyword in f.lower():
                    abs_file_path = os.path.join(root, f)
                    rel_path = os.path.relpath(abs_file_path, STORAGE_ROOT)
                    results.append({
                        "filename": f,
                        "user": username,
                        "rel_path": rel_path
                    })
    return render_template("search.html", keyword=keyword, results=results)

@app.errorhandler(403)
def error_403(e):
    return render_template("error.html", code=403, msg="Forbidden"), 403

@app.errorhandler(404)
def error_404(e):
    return render_template("error.html", code=404, msg="Not Found"), 404

# ============ 模板同前代码无改动，放入 templates 文件夹即可

if __name__ == "__main__":
    init_db()  # 启动时初始化数据库表
    app.run(host="0.0.0.0", port=8000, debug=True)
