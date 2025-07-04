import os
from flask import (
    Flask, request, redirect, url_for, flash, session, abort,
    send_from_directory, render_template_string
)
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'txt', 'md'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = 'your_production_secret_key_here_change_it'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

# -------- 数据库模型 --------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    notes = db.relationship('Note', backref='author', lazy=True)
    files = db.relationship('UploadFile', backref='owner', lazy=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class UploadFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    filetype = db.Column(db.String(20), nullable=False)  # image/video/text
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# ----- 工具函数 -----
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def lcs(a, b):
    n, m = len(a), len(b)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n):
        for j in range(m):
            if a[i] == b[j]:
                dp[i + 1][j + 1] = dp[i][j] + 1
            else:
                dp[i + 1][j + 1] = max(dp[i][j + 1], dp[i + 1][j])
    return dp[n][m]

def get_current_user():
    username = session.get('username')
    if username:
        return User.query.filter_by(username=username).first()
    return None

def login_required(func):
    from functools import wraps

    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not get_current_user():
            flash('请先登录', 'warning')
            return redirect(url_for('index'))
        return func(*args, **kwargs)

    return decorated_view

# -------- 模板 --------
base_html = '''
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}App{% endblock %}</title>
  <!-- Bootstrap 5.3 CDN -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">

  <style>
    /* 金色 + 红色主题 */
    :root {
      --bs-primary: #bfa243; /* 金色 */
      --bs-primary-rgb: 191, 162, 67;
      --bs-danger: #c9302c; /* 红色 */
      --bs-danger-rgb: 201, 48, 44;
    }
    nav.navbar {
      background-color: var(--bs-primary);
    }
    nav.navbar .navbar-brand,
    nav.navbar .nav-link {
      color: #800000;
      font-weight: 600;
    }
    nav.navbar .nav-link:hover {
      color: #ff2626;
    }
  </style>
  
  {% block head %}{% endblock %}
</head>
<body class="bg-light">

<nav class="navbar navbar-expand-lg mb-4">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('dashboard') }}">我的笔记与上传</a>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navmenu"
            aria-controls="navmenu" aria-expanded="false" aria-label="切换导航">
      <span class="navbar-toggler-icon"></span>
    </button>

    <div class="collapse navbar-collapse" id="navmenu">
      <ul class="navbar-nav ms-auto">
        {% if session.username %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('dashboard') }}">面板</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('search') }}">搜索用户</a></li>
          <li class="nav-item"><a class="nav-link" href="{{ url_for('profile', username=session.username) }}">我的主页</a></li>
          <li class="nav-item"><a class="nav-link text-danger" href="{{ url_for('logout') }}">退出登录</a></li>
        {% else %}
          <li class="nav-item"><a class="nav-link" href="{{ url_for('index') }}">登录</a></li>
        {% endif %}
      </ul>
    </div>
  </div>
</nav>

<div class="container mb-5">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, msg in messages %}
        <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
          {{ msg }}
          <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="关闭"></button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}

  {% block content %}{% endblock %}
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''

index_html = '''
{% extends base_html %}
{% block title %}登录{% endblock %}

{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6 col-lg-5 shadow p-4 bg-white rounded">
    <h2 class="mb-4 text-center text-danger">用户登录</h2>
    <form method="post" novalidate>
      <div class="mb-3">
        <label for="username" class="form-label">请输入用户名</label>
        <input type="text" class="form-control" id="username" name="username" placeholder="用户名" required>
      </div>
      <button type="submit" class="btn btn-warning w-100 fw-bold">登录</button>
    </form>
  </div>
</div>
{% endblock %}
'''

dashboard_html = '''
{% extends base_html %}
{% block title %}{{ user.username }} 的面板{% endblock %}

{% block content %}
<h1 class="mb-4 text-center" style="color:#bfa243;">欢迎，{{ user.username }}！</h1>

<div class="row">
  <div class="col-md-6 mb-4">

    <h3 class="text-danger">上传文件</h3>
    <form method="post" enctype="multipart/form-data" class="mb-3">
      <div class="input-group">
        <input type="file" name="file" class="form-control" accept=".png,.jpg,.jpeg,.gif,.mp4,.avi,.txt,.md" required>
        <button type="submit" class="btn btn-warning">上传</button>
      </div>
    </form>

    <h3 class="text-danger">写笔记</h3>
    <form method="post">
      <div class="mb-3">
        <textarea name="note" rows="4" class="form-control" placeholder="写点什么..." ></textarea>
      </div>
      <button type="submit" class="btn btn-warning fw-bold">保存笔记</button>
    </form>

  </div>

  <div class="col-md-6">

    <h3 class="text-danger">我的笔记</h3>
    {% if notes %}
      <ul class="list-group mb-4">
        {% for note in notes %}
        <li class="list-group-item d-flex justify-content-between align-items-start">
          <div class="flex-grow-1">{{ note.content|e }}</div>
          <div>
            <a href="{{ url_for('edit_note', note_id=note.id) }}" class="btn btn-sm btn-outline-warning me-1">编辑</a>
            <form method="post" action="{{ url_for('delete_note', note_id=note.id) }}" style="display:inline" onsubmit="return confirm('确定删除这条笔记？');">
              <button type="submit" class="btn btn-sm btn-outline-danger">删除</button>
            </form>
          </div>
        </li>
        {% endfor %}
      </ul>
    {% else %}
      <p class="text-muted">暂无笔记</p>
    {% endif %}

    <h3 class="text-danger">上传文件列表</h3>
    {% if uploads %}
      <ul class="list-group">
        {% for f in uploads %}
        <li class="list-group-item d-flex justify-content-between align-items-center">
          <a href="{{ url_for('uploaded_file', username=user.username, filename=f.filename) }}" target="_blank">{{ f.filename }}</a>
          <span>
            <span class="badge bg-warning text-dark me-3">{{ f.filetype }}</span>
            <form method="post" action="{{ url_for('delete_file', file_id=f.id) }}" style="display:inline" onsubmit="return confirm('确定删除此文件？');">
              <button type="submit" class="btn btn-sm btn-outline-danger">删除</button>
            </form>
          </span>
        </li>
        {% endfor %}
      </ul>
    {% else %}
      <p class="text-muted">暂无文件上传</p>
    {% endif %}

  </div>
</div>

{% endblock %}
'''

edit_note_html = '''
{% extends base_html %}
{% block title %}编辑笔记{% endblock %}

{% block content %}
<div class="row justify-content-center">
  <div class="col-md-8 col-lg-6 shadow p-4 bg-white rounded">
    <h2 class="mb-4 text-center text-danger">编辑笔记</h2>
    <form method="post" novalidate>
      <div class="mb-3">
        <textarea name="content" rows="10" class="form-control" required>{{ note.content|e }}</textarea>
      </div>
      <button type="submit" class="btn btn-warning w-100 fw-bold">保存</button>
    </form>
    <div class="mt-3 text-center">
      <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">取消</a>
    </div>
  </div>
</div>
{% endblock %}
'''

search_html = '''
{% extends base_html %}
{% block title %}搜索用户{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6 col-lg-5 shadow p-4 bg-white rounded">
    <h2 class="mb-4 text-center text-danger">搜索用户</h2>
    <form method="post" novalidate>
      <div class="mb-3">
        <input type="text" name="query" class="form-control" placeholder="请输入用户名搜索" required>
      </div>
      <button type="submit" class="btn btn-warning w-100 fw-bold">搜索</button>
    </form>
    <div class="mt-3 text-center">
      <a href="{{ url_for('dashboard') }}">返回我的面板</a>
    </div>
  </div>
</div>
{% endblock %}
'''

search_results_html = '''
{% extends base_html %}
{% block title %}搜索结果{% endblock %}
{% block content %}
<h2 class="text-center mb-4" style="color:#bfa243;">搜索结果: {{ query|e }}</h2>

{% if matches %}
  <ul class="list-group mb-4">
    {% for user in matches %}
    <li class="list-group-item d-flex justify-content-between align-items-center">
      <a href="{{ url_for('profile', username=user.username) }}">{{ user.username }}</a>
      <span class="badge bg-danger">{{ user.score }}</span>
    </li>
    {% endfor %}
  </ul>
{% else %}
  <p class="text-center text-muted">无匹配用户</p>
{% endif %}

<div class="text-center">
  <a href="{{ url_for('search') }}" class="btn btn-warning me-2">继续搜索</a>
  <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">返回面板</a>
</div>
{% endblock %}
'''

profile_html = '''
{% extends base_html %}
{% block title %}{{ user.username }} 的主页{% endblock %}
{% block content %}
<h1 class="text-center mb-4" style="color:#bfa243;">{{ user.username }} 的主页</h1>

{% if is_self %}
  <p class="text-center text-danger">这是你的主页。请前往<a href="{{ url_for('dashboard') }}">用户面板</a>编辑你的内容。</p>
{% endif %}

<h3 class="text-danger">笔记</h3>
{% if notes %}
  <ul class="list-group mb-4">
    {% for note in notes %}
    <li class="list-group-item">{{ note.content|e }}</li>
    {% endfor %}
  </ul>
{% else %}
  <p class="text-muted">无笔记</p>
{% endif %}

<h3 class="text-danger">上传文件</h3>
{% if uploads %}
  <ul class="list-group">
    {% for f in uploads %}
      <li class="list-group-item">
      {% if f.filetype == 'image' %}
        <div><strong>{{ f.filename }}</strong></div>
        <img src="{{ url_for('uploaded_file', username=user.username, filename=f.filename) }}" alt="{{ f.filename }}" class="img-fluid rounded mb-3" style="max-width:300px;">
      {% elif f.filetype == 'video' %}
        <div><strong>{{ f.filename }}</strong></div>
        <video controls preload="metadata" style="max-width: 320px; max-height: 240px;">
          <source src="{{ url_for('uploaded_file', username=user.username, filename=f.filename) }}" type="video/mp4">
          您的浏览器不支持视频播放。
        </video>
        <br><br>
      {% else %}
        <a href="{{ url_for('uploaded_file', username=user.username, filename=f.filename) }}" target="_blank">{{ f.filename }}</a> (文本文件)
      {% endif %}
      </li>
    {% endfor %}
  </ul>
{% else %}
  <p class="text-muted">无上传文件</p>
{% endif %}

<div class="text-center mt-4">
  <a href="{{ url_for('search') }}" class="btn btn-warning me-2">搜索用户</a>
  <a href="{{ url_for('dashboard') }}" class="btn btn-outline-secondary">返回面板</a>
</div>
{% endblock %}
'''

# -------- 路由 --------

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        if not username:
            flash('用户名不能为空', 'warning')
            return redirect(url_for('index'))
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['username'] = username
        flash(f'欢迎，{username}！', 'success')
        return redirect(url_for('dashboard'))
    return render_template_string(index_html, base_html=base_html)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('已退出登录', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user = get_current_user()

    if request.method == 'POST':
        # 上传文件
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                user_folder = os.path.join(app.config['UPLOAD_FOLDER'], user.username)
                os.makedirs(user_folder, exist_ok=True)
                save_path = os.path.join(user_folder, filename)
                file.save(save_path)

                ext = filename.rsplit('.', 1)[1].lower()
                if ext in ['png', 'jpg', 'jpeg', 'gif']:
                    ftype = 'image'
                elif ext in ['mp4', 'avi']:
                    ftype = 'video'
                else:
                    ftype = 'text'

                uploaded_file = UploadFile(filename=filename, filetype=ftype, user_id=user.id)
                db.session.add(uploaded_file)
                db.session.commit()
                flash(f'文件 "{filename}" 上传成功', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('文件格式不支持', 'danger')

        # 新建笔记
        if 'note' in request.form:
            content = request.form.get('note', '').strip()
            if content:
                note = Note(content=content, user_id=user.id)
                db.session.add(note)
                db.session.commit()
                flash('笔记保存成功', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('笔记内容不能为空', 'warning')

    notes = Note.query.filter_by(user_id=user.id).all()
    uploads = UploadFile.query.filter_by(user_id=user.id).all()
    return render_template_string(
        dashboard_html, base_html=base_html,
        user=user, notes=notes, uploads=uploads,
    )

@app.route('/note/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    user = get_current_user()
    note = Note.query.get_or_404(note_id)
    if note.user_id != user.id:
        abort(403)

    if request.method == 'POST':
        content = request.form.get('content', '').strip()
        if not content:
            flash('笔记内容不能为空', 'warning')
            return redirect(url_for('edit_note', note_id=note.id))
        note.content = content
        db.session.commit()
        flash('笔记更新成功', 'success')
        return redirect(url_for('dashboard'))

    return render_template_string(edit_note_html, base_html=base_html, note=note)

@app.route('/note/delete/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    user = get_current_user()
    note = Note.query.get_or_404(note_id)
    if note.user_id != user.id:
        abort(403)
    db.session.delete(note)
    db.session.commit()
    flash('笔记已删除', 'info')
    return redirect(url_for('dashboard'))

@app.route('/file/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    user = get_current_user()
    f = UploadFile.query.get_or_404(file_id)
    if f.user_id != user.id:
        abort(403)
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], user.username)
    file_path = os.path.join(user_folder, f.filename)
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception as e:
        flash(f'删除文件异常: {e}', 'danger')
    db.session.delete(f)
    db.session.commit()
    flash('文件已删除', 'info')
    return redirect(url_for('dashboard'))

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if not query:
            flash('请输入搜索内容', 'warning')
            return redirect(url_for('search'))

        users = User.query.all()
        scored_users = []
        for u in users:
            score = lcs(query.lower(), u.username.lower())
            scored_users.append((score, u))
        scored_users.sort(key=lambda x: x[0], reverse=True)
        matches = [{'username': u.username, 'score': s} for s, u in scored_users if s > 0]

        return render_template_string(
            search_results_html, base_html=base_html,
            query=query, matches=matches
        )
    return render_template_string(search_html, base_html=base_html)

@app.route('/profile/<string:username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    notes = Note.query.filter_by(user_id=user.id).all()
    uploads = UploadFile.query.filter_by(user_id=user.id).all()
    current_user = get_current_user()
    is_self = (current_user.username == user.username)
    return render_template_string(
        profile_html, base_html=base_html,
        user=user, notes=notes, uploads=uploads, is_self=is_self,
    )

@app.route('/uploads/<string:username>/<string:filename>')
def uploaded_file(username, filename):
    # 文件名安全处理
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)
    if not os.path.exists(os.path.join(user_folder, filename)):
        abort(404)
    return send_from_directory(user_folder, filename)

if __name__ == '__main__':
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
