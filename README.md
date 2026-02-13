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
- PostgreSQL: `localhost:5432`

Остановка:

```bash
docker compose down
```

Сброс БД (с удалением volume):

```bash
docker compose down -v
```
