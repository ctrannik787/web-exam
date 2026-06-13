# Электронная библиотека

Flask-приложение для ведения реестра книг, читателей и рецензий.

## Запуск

```powershell
python -m pip install -r requirements.txt
$env:FLASK_APP='app.py'
flask init-db
flask run --host 127.0.0.1 --port 5000
```

После запуска приложение доступно по адресу <http://127.0.0.1:5000/>.

## Тестовые пользователи

| Логин | Пароль | Роль |
| --- | --- | --- |
| admin | admin | администратор |
| moderator | moderator | модератор |
| user | user | пользователь |
| ivanov | ivanov | пользователь |
| petrova | petrova | пользователь |
| sidorov | sidorov | пользователь |

Для другой СУБД можно задать строку подключения через переменную окружения `DATABASE_URL`.

## Railway

Проект подготовлен для Railway:

- `railway.json` задаёт стартовую команду `python -m flask init-db && gunicorn app:app --bind 0.0.0.0:${PORT:-8000}`;
- `runtime.txt` фиксирует Python 3.12;
- `DATABASE_URL` автоматически используется для PostgreSQL, если добавить Railway PostgreSQL service;
- при старте создаются таблицы, роли, пользователи, книги, обложки и рецензии.

Рекомендуемые переменные окружения на Railway:

```text
SECRET_KEY=<длинная случайная строка>
DATABASE_URL=<автоматически появится при подключении PostgreSQL>
```
