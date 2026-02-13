FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY Task4.csproj ./
RUN dotnet restore Task4.csproj

COPY . ./
RUN dotnet publish Task4.csproj -c Release -o /app/publish /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgssapi-krb5-2 \
    && rm -rf /var/lib/apt/lists/*

ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production
ENV DATA_PROTECTION_KEYS_PATH=/var/data/dpkeys

COPY --from=build /app/publish ./

EXPOSE 8080
ENTRYPOINT ["dotnet", "Task4.dll"]
