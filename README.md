# Task4

Веб-приложение на ASP.NET Core MVC для управления пользователями:
- регистрация и вход;
- таблица пользователей с массовыми действиями (block/unblock/delete/delete unverified);
- PostgreSQL как хранилище.

## Технологии

- .NET 10
- ASP.NET Core MVC
- Entity Framework Core + Npgsql
- PostgreSQL
- Bootstrap

## Запуск локально (Docker)

Требования:
- Docker
- Docker Compose

Команда запуска:

```bash
docker compose up --build
```

После запуска:
- приложение: `http://localhost:8080`
- PostgreSQL: `localhost:5433`
- SMTP (Mailpit): `localhost:1025`
- Mailpit Web UI: `http://localhost:8025`

Остановка:

```bash
docker compose down
```

Сброс БД (с удалением volume):

```bash
docker compose down -v
```

## Применение обновления БД для существующего volume

`docker-entrypoint-initdb.d` выполняется только при первой инициализации БД.  
Если volume уже существует, примените SQL вручную:

```bash
docker compose exec -T db psql -U app_user -d app_db < docker/postgres/migrations/02-email-confirmation.sql
```

## Проверка подтверждения e-mail

1. Зарегистрируйте нового пользователя в приложении.
2. Откройте `http://localhost:8025`.
3. Входящее письмо содержит ссылку подтверждения `ConfirmEmail`.
4. После перехода по ссылке:
   - статус `unverified` меняется на `active`;
   - статус `blocked` остается `blocked`.
