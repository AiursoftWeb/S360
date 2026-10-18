# S360 - Supply-chain control

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/AiursoftWeb/S360/blob/master/LICENSE)
[![Pipeline stat](https://gitlab.aiursoft.com/aiursoft/s360/badges/master/pipeline.svg)](https://gitlab.aiursoft.com/aiursoft/s360/-/pipelines)
[![Test Coverage](https://gitlab.aiursoft.com/aiursoft/s360/badges/master/coverage.svg)](https://gitlab.aiursoft.com/aiursoft/s360/-/pipelines)
[![Man hours](https://manhours.aiursoft.com/r/github.com/AiursoftWeb/S360.svg)](https://manhours.aiursoft.com/r/github.com/AiursoftWeb/S360.html)
[![Website](https://img.shields.io/website?url=https%3A%2F%2Fs360.aiursoft.com)](https://s360.aiursoft.com)
[![Docker](https://img.shields.io/docker/pulls/aiursoft/s360.svg)](https://hub.docker.com/r/aiursoft/s360)

S360 manages NuGet and npm dependencies: employees request packages, reviewers approve dependency graphs, and teams track package files, trust rules, blocklists, and vulnerabilities.

![S360 screenshot](./screenshot.png)

## Try

Try the S360 Web pilot [here](https://s360.aiursoft.com) with your company account. Runner integration and CI enforcement have not been enabled.

## Run manually

1. Install the .NET 10 SDK and Node.js/npm.
2. Run `npm ci --prefix src/Aiursoft.S360/wwwroot` and `npm run build --prefix src/Aiursoft.S360/wwwroot`.
3. Run `dotnet run --project src/Aiursoft.S360` and open the URL printed by the application.

The defaults use SQLite and local accounts. Configure authentication, database, and storage through [appsettings.json](src/Aiursoft.S360/appsettings.json) or environment variables.

## Run in Microsoft Visual Studio

1. Open the `.sln` file in the project path.
2. Press `F5` to run the app.

## Run in Docker

```bash
image=aiursoft/s360
appName=s360
sudo docker pull $image
sudo docker run -d --name $appName --restart unless-stopped -p 5000:5000 -v /var/www/$appName:/data $image
```

Open `http://localhost:5000`. Keep `/data` persistent for configuration, database, uploaded files, and Data Protection keys.

| Properties  | Value                  |
|-------------|------------------------|
| Image       | aiursoft/s360          |
| Ports       | 5000                   |
| Binary path | /app                   |
| Data path   | /data                  |
| Config path | /data/appsettings.json |

For company sign-in, configure `AppSettings__AuthProvider=OIDC` and the `AppSettings__OIDC__*` values. Keep client secrets outside Git and assign application permissions to the appropriate roles.

## Dependency checks

The `s360 check --path .` CLI checks restored NuGet and npm inputs against the server policy. It requires `S360_SERVER` and `S360_CHECK_KEY`; run `dotnet restore` and `npm ci` first. The API key needs `CanCheckDependencies` permission and must stay out of source and logs.

By default, `--purpose review` records an audit without changing production usage. Use `--purpose baseline` only to declare dependencies already in production; it requires a separate `SupplyChain__BaselineApiKey` supplied as `S360_CHECK_KEY`. Keep that key restricted to trusted release jobs. Only a complete baseline replaces the project inventory, including when its dependencies are rejected.

Use `--ecosystem nuget` for a NuGet-only gate, or `--ecosystem npm` for npm; the default checks both. A scoped baseline updates only that ecosystem.

Configure permitted registries through `SupplyChain:NuGetSources` and `SupplyChain:NpmSources`. Dependency resolution restores untrusted packages; run it in an isolated environment. The check does not prove installed files were unchanged by package scripts.

## How to contribute

Report bugs and suggestions through the issue tracker. Create a fork and a feature branch, then submit a merge request for review.
