from __future__ import annotations

import hashlib
import os
from datetime import datetime
from html import escape
from pathlib import Path

import bleach
import markdown
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, UniqueConstraint, event, func
from sqlalchemy.engine import Engine
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads" / "covers"

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.login_message = "Для выполнения данного действия необходимо пройти процедуру аутентификации"
login_manager.login_message_category = "warning"

book_genres = db.Table(
    "book_genres",
    db.Column("book_id", db.Integer, db.ForeignKey("books.id", ondelete="CASCADE"), primary_key=True),
    db.Column("genre_id", db.Integer, db.ForeignKey("genres.id", ondelete="CASCADE"), primary_key=True),
)


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    middle_name = db.Column(db.String(80))
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="RESTRICT"), nullable=False)

    role = db.relationship("Role")
    reviews = db.relationship("Review", back_populates="user", cascade="all, delete-orphan")

    @property
    def full_name(self) -> str:
        return " ".join(filter(None, [self.last_name, self.first_name, self.middle_name]))

    @property
    def role_name(self) -> str:
        return self.role.name if self.role else ""

    def can_edit_books(self) -> bool:
        return self.role_name in {"administrator", "moderator"}

    def can_delete_books(self) -> bool:
        return self.role_name == "administrator"


class Genre(db.Model):
    __tablename__ = "genres"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)


class Book(db.Model):
    __tablename__ = "books"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    publisher = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(255), nullable=False)
    pages = db.Column(db.Integer, nullable=False)

    genres = db.relationship("Genre", secondary=book_genres, backref=db.backref("books", lazy="dynamic"))
    cover = db.relationship("Cover", back_populates="book", uselist=False, cascade="all, delete-orphan")
    reviews = db.relationship("Review", back_populates="book", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("year >= 0", name="ck_books_year_positive"),
        CheckConstraint("pages > 0", name="ck_books_pages_positive"),
    )

    @property
    def average_rating(self):
        values = [review.rating for review in self.reviews]
        return round(sum(values) / len(values), 1) if values else None


class Cover(db.Model):
    __tablename__ = "covers"

    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(128), nullable=False)
    md5_hash = db.Column(db.String(32), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey("books.id", ondelete="CASCADE"), nullable=False, unique=True)

    book = db.relationship("Book", back_populates="cover")


class Review(db.Model):
    __tablename__ = "reviews"

    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey("books.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, server_default=func.now())

    book = db.relationship("Book", back_populates="reviews")
    user = db.relationship("User", back_populates="reviews")

    __table_args__ = (
        CheckConstraint("rating BETWEEN 0 AND 5", name="ck_reviews_rating_range"),
        UniqueConstraint("book_id", "user_id", name="uq_reviews_book_user"),
    )


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if not dbapi_connection.__class__.__module__.startswith("sqlite3"):
        return
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-change-me")
    database_url = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'library.db'}")
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif database_url.startswith("postgresql://"):
        database_url = database_url.replace("postgresql://", "postgresql+psycopg://", 1)
    app.config["SQLALCHEMY_DATABASE_URI"] = database_url
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

    db.init_app(app)
    login_manager.init_app(app)
    register_commands(app)
    register_routes(app)
    return app


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


def register_commands(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db():
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        db.create_all()
        seed_data()
        print("Database initialized with roles, genres, users, books and covers.")


def seed_data() -> None:
    roles = {
        "administrator": "Суперпользователь, имеет полный доступ к системе.",
        "moderator": "Может редактировать книги и модерировать рецензии.",
        "user": "Может оставлять рецензии.",
    }
    for name, description in roles.items():
        if not Role.query.filter_by(name=name).first():
            db.session.add(Role(name=name, description=description))

    for name in [
        "Роман",
        "Фантастика",
        "Научная литература",
        "История",
        "Детектив",
        "Поэзия",
        "Повесть",
        "Драма",
        "Приключения",
        "Антиутопия",
        "Философская проза",
        "Сказка",
        "Социальная проза",
    ]:
        if not Genre.query.filter_by(name=name).first():
            db.session.add(Genre(name=name))
    db.session.flush()

    users = [
        ("admin", "admin", "Борисов", "Администратор", "", "administrator"),
        ("moderator", "moderator", "Борисов", "Модератор", "", "moderator"),
        ("user", "user", "Борисов", "Пользователь", "", "user"),
        ("ivanov", "ivanov", "Иванов", "Алексей", "Петрович", "user"),
        ("petrova", "petrova", "Петрова", "Мария", "Сергеевна", "user"),
        ("sidorov", "sidorov", "Сидоров", "Дмитрий", "Игоревич", "user"),
    ]
    for login, password, last_name, first_name, middle_name, role_name in users:
        if not User.query.filter_by(login=login).first():
            db.session.add(
                User(
                    login=login,
                    password_hash=generate_password_hash(password),
                    last_name=last_name,
                    first_name=first_name,
                    middle_name=middle_name or None,
                    role=Role.query.filter_by(name=role_name).first(),
                )
            )
    seed_books()
    seed_reviews()
    db.session.commit()


def seed_books() -> None:
    books = [
        {
            "title": "Война и мир",
            "author": "Лев Толстой",
            "year": 1869,
            "publisher": "Русский вестник",
            "pages": 1225,
            "genres": ["Роман", "История"],
            "description": "Эпический роман о судьбах нескольких дворянских семей на фоне Отечественной войны 1812 года.",
            "colors": ("#4c1d1d", "#d6b46d"),
        },
        {
            "title": "Преступление и наказание",
            "author": "Фёдор Достоевский",
            "year": 1866,
            "publisher": "Русский вестник",
            "pages": 672,
            "genres": ["Роман", "Философская проза"],
            "description": "Психологический роман о преступлении, совести и поиске нравственного выхода.",
            "colors": ("#1f2937", "#ef4444"),
        },
        {
            "title": "Мастер и Маргарита",
            "author": "Михаил Булгаков",
            "year": 1967,
            "publisher": "Москва",
            "pages": 480,
            "genres": ["Роман", "Фантастика"],
            "description": "Сатирический и мистический роман о Москве, любви, творчестве и свободе.",
            "colors": ("#111827", "#f59e0b"),
        },
        {
            "title": "Евгений Онегин",
            "author": "Александр Пушкин",
            "year": 1833,
            "publisher": "Типография Департамента народного просвещения",
            "pages": 224,
            "genres": ["Роман", "Поэзия"],
            "description": "Роман в стихах о любви, светской жизни и выборе, ставший классикой русской литературы.",
            "colors": ("#312e81", "#c4b5fd"),
        },
        {
            "title": "Отцы и дети",
            "author": "Иван Тургенев",
            "year": 1862,
            "publisher": "Русский вестник",
            "pages": 288,
            "genres": ["Роман", "Социальная проза"],
            "description": "Роман о конфликте поколений и мировоззрений в России XIX века.",
            "colors": ("#14532d", "#86efac"),
        },
        {
            "title": "Анна Каренина",
            "author": "Лев Толстой",
            "year": 1877,
            "publisher": "Русский вестник",
            "pages": 864,
            "genres": ["Роман", "Драма"],
            "description": "Роман о любви, семье, нравственном выборе и противоречиях общества.",
            "colors": ("#7f1d1d", "#fecaca"),
        },
        {
            "title": "Тихий Дон",
            "author": "Михаил Шолохов",
            "year": 1940,
            "publisher": "Гослитиздат",
            "pages": 1504,
            "genres": ["Роман", "История"],
            "description": "Роман-эпопея о донском казачестве в годы войны, революции и гражданского противостояния.",
            "colors": ("#0f766e", "#99f6e4"),
        },
        {
            "title": "Мёртвые души",
            "author": "Николай Гоголь",
            "year": 1842,
            "publisher": "Университетская типография",
            "pages": 352,
            "genres": ["Роман", "Социальная проза"],
            "description": "Сатирическое путешествие Чичикова по помещичьей России.",
            "colors": ("#3f3f46", "#e4e4e7"),
        },
        {
            "title": "Гарри Поттер и философский камень",
            "author": "Джоан Роулинг",
            "year": 1997,
            "publisher": "Bloomsbury",
            "pages": 352,
            "genres": ["Фантастика", "Приключения"],
            "description": "Первая книга о мальчике-волшебнике, школе Хогвартс и начале большого приключения.",
            "colors": ("#581c87", "#facc15"),
        },
        {
            "title": "Властелин колец",
            "author": "Джон Р. Р. Толкин",
            "year": 1954,
            "publisher": "Allen & Unwin",
            "pages": 1216,
            "genres": ["Фантастика", "Приключения"],
            "description": "Фэнтезийная эпопея о путешествии к Роковой горе и борьбе со злом Средиземья.",
            "colors": ("#064e3b", "#fbbf24"),
        },
        {
            "title": "1984",
            "author": "Джордж Оруэлл",
            "year": 1949,
            "publisher": "Secker & Warburg",
            "pages": 328,
            "genres": ["Антиутопия", "Фантастика"],
            "description": "Антиутопия о тотальном контроле, языке власти и сопротивлении личности.",
            "colors": ("#020617", "#38bdf8"),
        },
        {
            "title": "Маленький принц",
            "author": "Антуан де Сент-Экзюпери",
            "year": 1943,
            "publisher": "Reynal & Hitchcock",
            "pages": 112,
            "genres": ["Сказка", "Философская проза"],
            "description": "Философская сказка о дружбе, ответственности и умении видеть главное.",
            "colors": ("#1d4ed8", "#fde68a"),
        },
        {
            "title": "Убить пересмешника",
            "author": "Харпер Ли",
            "year": 1960,
            "publisher": "J. B. Lippincott & Co.",
            "pages": 384,
            "genres": ["Роман", "Социальная проза"],
            "description": "Роман о взрослении, справедливости и предрассудках на американском Юге.",
            "colors": ("#713f12", "#fed7aa"),
        },
        {
            "title": "Над пропастью во ржи",
            "author": "Джером Д. Сэлинджер",
            "year": 1951,
            "publisher": "Little, Brown and Company",
            "pages": 288,
            "genres": ["Роман", "Повесть"],
            "description": "История Холдена Колфилда, его одиночества, протеста и болезненного взросления.",
            "colors": ("#991b1b", "#fca5a5"),
        },
        {
            "title": "Гордость и предубеждение",
            "author": "Джейн Остин",
            "year": 1813,
            "publisher": "T. Egerton",
            "pages": 432,
            "genres": ["Роман", "Драма"],
            "description": "Классический роман о любви, характере, социальных ожиданиях и ошибках первого впечатления.",
            "colors": ("#831843", "#f9a8d4"),
        },
    ]

    for item in books:
        book = Book.query.filter_by(title=item["title"], author=item["author"]).first()
        if not book:
            book = Book(
                title=item["title"],
                description=item["description"],
                year=item["year"],
                publisher=item["publisher"],
                author=item["author"],
                pages=item["pages"],
            )
            book.genres = Genre.query.filter(Genre.name.in_(item["genres"])).all()
            db.session.add(book)
            db.session.flush()
        if not book.cover:
            create_seed_cover(book, item["colors"])


def create_seed_cover(book: Book, colors: tuple[str, str]) -> None:
    data = render_cover_svg(book.title, book.author, book.year, colors)
    md5_hash = hashlib.md5(data).hexdigest()
    existing = Cover.query.filter_by(md5_hash=md5_hash).first()
    cover = Cover(
        filename=existing.filename if existing else "seed-cover.svg",
        mime_type="image/svg+xml",
        md5_hash=md5_hash,
        book=book,
    )
    db.session.add(cover)
    db.session.flush()
    if existing:
        return
    cover.filename = f"{cover.id}.svg"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    cover_file_path(cover).write_bytes(data)


def render_cover_svg(title: str, author: str, year: int, colors: tuple[str, str]) -> bytes:
    width, height = 720, 1080
    title_lines = wrap_cover_text(title.upper(), 18)
    author_lines = wrap_cover_text(author, 26)
    accent = colors[1]
    title_svg = "\n".join(
        f'<text x="360" y="{300 + index * 74}" class="title">{escape(line)}</text>'
        for index, line in enumerate(title_lines)
    )
    author_svg = "\n".join(
        f'<text x="360" y="{735 + index * 42}" class="author">{escape(line)}</text>'
        for index, line in enumerate(author_lines)
    )
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<defs>
  <linearGradient id="paper" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0%" stop-color="{colors[0]}"/>
    <stop offset="100%" stop-color="#111827"/>
  </linearGradient>
  <pattern id="lines" width="36" height="36" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
    <line x1="0" y1="0" x2="0" y2="36" stroke="#ffffff" stroke-opacity="0.06" stroke-width="4"/>
  </pattern>
</defs>
<rect width="720" height="1080" fill="url(#paper)"/>
<rect width="720" height="1080" fill="url(#lines)"/>
<rect x="48" y="48" width="624" height="984" fill="none" stroke="{accent}" stroke-width="6"/>
<rect x="78" y="78" width="564" height="924" fill="none" stroke="{accent}" stroke-width="2" opacity="0.75"/>
<line x1="120" y1="250" x2="600" y2="250" stroke="{accent}" stroke-width="4"/>
<line x1="120" y1="850" x2="600" y2="850" stroke="{accent}" stroke-width="4"/>
<style>
  .title {{ font-family: Arial, DejaVu Sans, sans-serif; font-size: 58px; font-weight: 700; text-anchor: middle; fill: {accent}; letter-spacing: 1px; }}
  .author {{ font-family: Arial, DejaVu Sans, sans-serif; font-size: 34px; font-weight: 500; text-anchor: middle; fill: #f8fafc; }}
  .year {{ font-family: Arial, DejaVu Sans, sans-serif; font-size: 42px; font-weight: 700; text-anchor: middle; fill: {accent}; }}
</style>
{title_svg}
{author_svg}
<text x="360" y="930" class="year">{year}</text>
</svg>"""
    return svg.encode("utf-8")


def wrap_cover_text(text: str, limit: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= limit or not current:
            current = candidate
        else:
            lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines[:6]


def seed_reviews() -> None:
    reviews = [
        ("Мастер и Маргарита", "ivanov", 5, "Сильный роман: мистика, сатира и линия Маргариты держат внимание до конца."),
        ("Мастер и Маргарита", "petrova", 5, "Очень атмосферная книга. Особенно понравилось, как переплетаются московские и библейские главы."),
        ("Война и мир", "sidorov", 4, "Масштабное произведение, местами читается неспешно, но персонажи раскрыты великолепно."),
        ("Война и мир", "user", 5, "Классика, в которой исторические события ощущаются через частные судьбы героев."),
        ("Преступление и наказание", "ivanov", 5, "Тяжёлая, но захватывающая история о совести и внутреннем переломе человека."),
        ("Преступление и наказание", "petrova", 4, "Психологически очень точный роман, хотя настроение у книги довольно мрачное."),
        ("Евгений Онегин", "user", 5, "Лёгкий слог, точные наблюдения и запоминающиеся герои. Читается удивительно живо."),
        ("Анна Каренина", "petrova", 5, "Глубокий роман о чувствах, семье и выборе. Многие сцены остаются в памяти."),
        ("Отцы и дети", "sidorov", 4, "Хорошо показан конфликт поколений, а Базаров получился очень неоднозначным героем."),
        ("Тихий Дон", "ivanov", 5, "Большая и драматичная книга, особенно сильны описания жизни казачества и переломной эпохи."),
        ("Гарри Поттер и философский камень", "user", 5, "Добрая и увлекательная история, с которой легко начать знакомство с серией."),
        ("Гарри Поттер и философский камень", "petrova", 4, "Книга простая, но очень уютная: мир Хогвартса сразу цепляет."),
        ("Властелин колец", "sidorov", 5, "Эпическое приключение с продуманным миром и ощущением настоящего пути."),
        ("1984", "ivanov", 5, "Сильная антиутопия, которая пугает не фантастикой, а узнаваемостью механизмов контроля."),
        ("1984", "user", 4, "Идеи мощные, но текст местами давит своей безысходностью."),
        ("Маленький принц", "petrova", 5, "Короткая, светлая и мудрая сказка, к которой хочется возвращаться."),
        ("Убить пересмешника", "sidorov", 5, "Очень человечная книга о справедливости, взрослении и достоинстве."),
        ("Над пропастью во ржи", "ivanov", 3, "Интересный голос героя, но его раздражение и растерянность не всегда легко выдержать."),
        ("Гордость и предубеждение", "petrova", 5, "Остроумный и тонкий роман, где характеры раскрываются через диалоги и поступки."),
        ("Мёртвые души", "user", 4, "Сатирическая классика с яркими образами помещиков и очень узнаваемыми типажами."),
    ]

    for title, user_login, rating, text in reviews:
        book = Book.query.filter_by(title=title).first()
        user = User.query.filter_by(login=user_login).first()
        if not book or not user:
            continue
        exists = Review.query.filter_by(book_id=book.id, user_id=user.id).first()
        if exists:
            continue
        db.session.add(Review(book=book, user=user, rating=rating, text=sanitize_markdown(text)))


def register_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        page = request.args.get("page", 1, type=int)
        query = Book.query

        title = request.args.get("title", "").strip()
        author = request.args.get("author", "").strip()
        genre_ids = [int(value) for value in request.args.getlist("genres") if value.isdigit()]
        years = [int(value) for value in request.args.getlist("years") if value.isdigit()]
        pages_from = request.args.get("pages_from", "").strip()
        pages_to = request.args.get("pages_to", "").strip()

        if title:
            query = query.filter(Book.title.ilike(f"%{title}%"))
        if author:
            query = query.filter(Book.author.ilike(f"%{author}%"))
        if genre_ids:
            query = query.filter(Book.genres.any(Genre.id.in_(genre_ids)))
        if years:
            query = query.filter(Book.year.in_(years))
        if pages_from.isdigit():
            query = query.filter(Book.pages >= int(pages_from))
        if pages_to.isdigit():
            query = query.filter(Book.pages <= int(pages_to))

        pagination = query.order_by(Book.year.desc(), Book.id.desc()).paginate(page=page, per_page=10, error_out=False)
        years_available = [row[0] for row in db.session.query(Book.year).distinct().order_by(Book.year.desc()).all()]
        return render_template(
            "index.html",
            pagination=pagination,
            books=pagination.items,
            genres=Genre.query.order_by(Genre.name).all(),
            years_available=years_available,
            selected_genres=genre_ids,
            selected_years=years,
            filter_args={k: v for k, v in request.args.to_dict(flat=False).items() if k != "page"},
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for("index"))
        if request.method == "POST":
            user = User.query.filter_by(login=request.form.get("login", "").strip()).first()
            password = request.form.get("password", "")
            if user and check_password_hash(user.password_hash, password):
                login_user(user, remember=bool(request.form.get("remember")))
                return redirect(request.args.get("next") or url_for("index"))
            flash("Невозможно аутентифицироваться с указанными логином и паролем", "danger")
        return render_template("login.html")

    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(request.referrer or url_for("index"))

    @app.route("/books/add", methods=["GET", "POST"])
    @login_required
    @role_required("administrator")
    def add_book():
        return save_book()

    @app.route("/books/<int:book_id>/edit", methods=["GET", "POST"])
    @login_required
    @role_required("administrator", "moderator")
    def edit_book(book_id):
        book = db.get_or_404(Book, book_id)
        return save_book(book)

    @app.route("/books/<int:book_id>/delete", methods=["POST"])
    @login_required
    @role_required("administrator")
    def delete_book(book_id):
        book = db.get_or_404(Book, book_id)
        cover_path = cover_file_path(book.cover) if book.cover else None
        shared_cover_count = 0
        if book.cover:
            shared_cover_count = Cover.query.filter(Cover.filename == book.cover.filename, Cover.id != book.cover.id).count()
        try:
            db.session.delete(book)
            db.session.commit()
            if cover_path and cover_path.exists() and shared_cover_count == 0:
                cover_path.unlink()
            flash("Книга успешно удалена", "success")
        except Exception:
            db.session.rollback()
            flash("При удалении книги возникла ошибка", "danger")
        return redirect(url_for("index"))

    @app.route("/books/<int:book_id>")
    def view_book(book_id):
        book = db.get_or_404(Book, book_id)
        user_review = None
        if current_user.is_authenticated:
            user_review = Review.query.filter_by(book_id=book.id, user_id=current_user.id).first()
        return render_template("book_view.html", book=book, user_review=user_review)

    @app.route("/books/<int:book_id>/reviews/add", methods=["GET", "POST"])
    @login_required
    def add_review(book_id):
        book = db.get_or_404(Book, book_id)
        existing = Review.query.filter_by(book_id=book.id, user_id=current_user.id).first()
        if existing:
            flash("Вы уже оставили рецензию на эту книгу", "warning")
            return redirect(url_for("view_book", book_id=book.id))
        if request.method == "POST":
            try:
                review = Review(
                    book=book,
                    user=current_user,
                    rating=int(request.form.get("rating", 5)),
                    text=sanitize_markdown(request.form.get("text", "")),
                )
                db.session.add(review)
                db.session.commit()
                flash("Рецензия успешно добавлена", "success")
                return redirect(url_for("view_book", book_id=book.id))
            except Exception:
                db.session.rollback()
                flash("При сохранении рецензии возникла ошибка", "danger")
        return render_template("review_form.html", book=book, rating_options=rating_options())

    @app.route("/reviews/<int:review_id>/delete", methods=["POST"])
    @login_required
    @role_required("administrator", "moderator")
    def delete_review(review_id):
        review = db.get_or_404(Review, review_id)
        book_id = review.book_id
        try:
            db.session.delete(review)
            db.session.commit()
            flash("Рецензия удалена", "success")
        except Exception:
            db.session.rollback()
            flash("При удалении рецензии возникла ошибка", "danger")
        return redirect(url_for("view_book", book_id=book_id))

    @app.route("/covers/<path:filename>")
    def cover_file(filename):
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

    @app.template_filter("markdown")
    def markdown_filter(text: str) -> str:
        html = markdown.markdown(text or "", extensions=["extra", "nl2br"])
        return sanitize_html(html)


def role_required(*roles):
    def decorator(view):
        def wrapped(*args, **kwargs):
            if current_user.role_name not in roles:
                flash("У вас недостаточно прав для выполнения данного действия", "danger")
                return redirect(url_for("index"))
            return view(*args, **kwargs)

        wrapped.__name__ = view.__name__
        return wrapped

    return decorator


def save_book(book: Book | None = None):
    genres = Genre.query.order_by(Genre.name).all()
    is_create = book is None
    if is_create:
        book = Book()

    if request.method == "POST":
        try:
            book.title = request.form.get("title", "").strip()
            book.description = sanitize_markdown(request.form.get("description", ""))
            book.year = int(request.form.get("year", ""))
            book.publisher = request.form.get("publisher", "").strip()
            book.author = request.form.get("author", "").strip()
            book.pages = int(request.form.get("pages", ""))
            selected_genres = [int(value) for value in request.form.getlist("genres") if value.isdigit()]
            book.genres = Genre.query.filter(Genre.id.in_(selected_genres)).all()
            if not book.genres:
                raise ValueError("book must have at least one genre")

            if is_create:
                cover = request.files.get("cover")
                if not cover or not cover.filename:
                    raise ValueError("cover is required")
                db.session.add(book)
                db.session.flush()
                create_cover(book, cover)

            db.session.commit()
            flash("Данные книги успешно сохранены", "success")
            return redirect(url_for("view_book", book_id=book.id))
        except Exception:
            db.session.rollback()
            flash("При сохранении данных возникла ошибка. Проверьте корректность введённых данных.", "danger")

    return render_template("book_form.html", book=book, genres=genres, is_create=is_create)


def create_cover(book: Book, file_storage) -> None:
    data = file_storage.read()
    if not data or not (file_storage.mimetype or "").startswith("image/"):
        raise ValueError("cover must be an image")
    md5_hash = hashlib.md5(data).hexdigest()
    existing = Cover.query.filter_by(md5_hash=md5_hash).first()
    original_name = secure_filename(file_storage.filename) or "cover"
    extension = Path(original_name).suffix.lower()
    cover = Cover(filename=original_name, mime_type=file_storage.mimetype, md5_hash=md5_hash, book=book)
    db.session.add(cover)
    db.session.flush()
    cover.filename = existing.filename if existing else f"{cover.id}{extension}"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    if not existing:
        cover_file_path(cover).write_bytes(data)


def cover_file_path(cover: Cover) -> Path:
    return UPLOAD_DIR / cover.filename


def sanitize_markdown(value: str) -> str:
    return bleach.clean(value or "", tags=allowed_html_tags(), strip=True)


def sanitize_html(value: str) -> str:
    return bleach.clean(
        value or "",
        tags=allowed_html_tags(),
        attributes={"a": ["href", "title"], "abbr": ["title"], "acronym": ["title"]},
        protocols=["http", "https", "mailto"],
        strip=True,
    )


def allowed_html_tags() -> set[str]:
    allowed_tags = set(bleach.sanitizer.ALLOWED_TAGS) | {
        "p",
        "pre",
        "code",
        "h1",
        "h2",
        "h3",
        "h4",
        "ul",
        "ol",
        "li",
        "blockquote",
        "br",
    }
    return allowed_tags


def rating_options():
    return [
        (5, "отлично"),
        (4, "хорошо"),
        (3, "удовлетворительно"),
        (2, "неудовлетворительно"),
        (1, "плохо"),
        (0, "ужасно"),
    ]


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
