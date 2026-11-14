# S360 - Supply-chain control

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/AiursoftWeb/S360/blob/master/LICENSE)
[![Pipeline stat](https://badge-proxy.aiursoft.com/aiursoft/s360/badges/master/pipeline.svg)](https://gitlab.aiursoft.com/aiursoft/s360/-/pipelines)
[![Test Coverage](https://badge-proxy.aiursoft.com/aiursoft/s360/badges/master/coverage.svg)](https://gitlab.aiursoft.com/aiursoft/s360/-/pipelines)
[![S360 compliance](https://s360.aiursoft.com/badge.svg?project=aiursoft%2Fs360)](https://s360.aiursoft.com/SupplyChain?tab=projects&project=aiursoft%2Fs360&scope=baseline&ecosystem=all)
[![Man hours](https://manhours.aiursoft.com/r/github.com/AiursoftWeb/S360.svg)](https://manhours.aiursoft.com/r/github.com/AiursoftWeb/S360.html)
[![Website](https://img.shields.io/website?url=https%3A%2F%2Fs360.aiursoft.com)](https://s360.aiursoft.com)
[![Docker](https://img.shields.io/docker/pulls/aiursoft/s360.svg)](https://hub.docker.com/r/aiursoft/s360)

S360 records which NuGet and npm packages your team may use, checks known vulnerabilities, and alerts affected projects. Package servers handle downloading, integrity checks, and caching.

## CLI & SDK

Install the CLI with the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0):

```bash
dotnet tool install --global Aiursoft.S360.Client
```

Run `s360 --help` to explore commands. See [Dependency checks](#dependency-checks) for configuration and examples.

The [SDK source](src/Aiursoft.S360.SDK) is included in this repository; it is not published as a separate NuGet package.

![S360 screenshot](./screenshot.png)

## Try

Try [S360](https://s360.aiursoft.com) with your company account.

## Install with Docker

Run the installer with the desired port (omit it to choose an available port):

```bash
curl -fsSL https://raw.githubusercontent.com/aiursoftweb/s360/master/install.sh | sudo bash -s -- 8080
```

Installation starts after three seconds; press Ctrl+C to cancel. Then open `http://localhost:8080`.

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

The CLI checks restored dependencies against the server policy. NuGet checks require an explicit `.sln` file and the .NET SDK. Use the same solution and environment for restore, check and build:

```bash
dotnet restore App.sln
s360 check --ecosystem nuget --path App.sln
dotnet build App.sln --no-restore
```

The solution's restore graph includes referenced projects even when they are not listed in the solution. Unrelated projects are excluded; missing or stale restore output inside the graph still fails. The check evaluates the graph without restoring packages. Restore with the default solution configuration; custom MSBuild command-line properties are not forwarded by the checker.

For an npm gate before installation, use CLI 1.4.0 or later:

```bash
s360 check --ecosystem npm --path . --npm-lockfile-only --purpose review
# Continue only after a successful check; npm ci uses the same checked-in lockfile.
npm ci
npm run build
```

This mode reads the locked package names, versions, and sources without downloading archives or running package scripts. It includes optional packages for other platforms, so a Linux check also covers packages later selected by an ARM64 or Windows build. It reports the locked dependency set, not an observed installation. Use `--purpose baseline` with the existing credential for production reports. Keep the manifest and lockfile unchanged between checking and building; subsequent builds must use `npm ci`, not `npm install`.

When CI uses `replace-registry-host=always`, pass `--npm-registry https://nopkg.aiursoft.com/npm/` to audit the same registry used by npm. The selected registry is reported as the package source; the lockfile stays unchanged. npm remains responsible for archive integrity and installation. Direct archive URLs are rejected in this mode. Omit the option to retain the original lockfile-source checks. Selected registries with path prefixes (such as `/npm`) are validated and reported with that full prefix.

Without `--npm-lockfile-only`, run `npm ci --ignore-scripts` first, then `s360 check --ecosystem npm --path .`; this existing mode validates the current installation and skips absent optional packages. The default ecosystem (`all`) requires a solution and also checks npm projects under its directory. From CLI 1.1.0, directory-only NuGet/all calls must pass the solution file instead.

The CLI requires `S360_SERVER` and normally `S360_CHECK_KEY`. Create a personal key under **Personal → API Keys** with `CanManageApiKeys` permission; keep it out of source and logs.

By default, `--purpose review` checks policy without saving project reports or changing production inventory. Approved version ranges cover new versions without file verification. If vulnerability data needs refreshing, the existing background audit is queued. The CLI polls every 15 seconds for up to 10 minutes; missing approval, revoked rules and known vulnerabilities remain blocking. Use `--purpose baseline` only to declare dependencies already in production; it requires a baseline-enabled personal key and the owner’s current `CanPublishBaselines` permission, supplied as `S360_CHECK_KEY`. Keep that key restricted to trusted release jobs. Only a complete baseline replaces the project inventory, including when its dependencies are rejected.

Administrators can enable **Allow anonymous review** in Global Settings (default: disabled). Then review checks may omit the key; results are returned only to the caller. Baseline always requires an authorized key. Checks are limited to 120 requests per minute per client IP. Anonymous reviews also share four concurrent slots; repeated requests coalesce vulnerability refreshes.

Rotate keys by creating a second key, switching the caller and verifying it, then deleting the old key. Keys expire and can be disabled independently; removing the owner’s API permission or locking the account revokes access. Legacy configured check/baseline keys are no longer accepted.

Use `--ecosystem nuget` for a NuGet-only gate, or `--ecosystem npm` for npm; the default checks both. A scoped baseline updates only that ecosystem.

CLI 1.0.10 and later also report manifest-scoped dependency relationships. Open a project in **Supply chain → Projects** to explore its NuGet/npm graphs and current compliance; older reports retain their package lists until a new check is submitted.

Configure permitted registries through `SupplyChain:NuGetSources` and `SupplyChain:NpmSources`. S360 treats these URLs as policy identities; it does not contact them. Requests contain package names and versions, and CI reports resolved dependency lists. S360 never restores dependencies or downloads package archives.

## Package server integration

Package servers query the existing `POST /api/artifacts/assess` endpoint with a personal `X-S360-Key`. Each dependency contains `ecosystem`, `name`, `version`, and `source`; no package file or hash is required. The response reports whether current rules and vulnerability data allow that version. Baseline permission is not required.

A registry can use its internal distribution URL as the policy source. Approve the package once for that source; the registry chooses and contacts its upstream. S360 requires no upstream mapping and never calls a registry.

Recheck before serving cached packages so revocation and new vulnerabilities take effect. Unavailable or stale vulnerability data is reported as pending, not as a clean result. Project inventory and AlertCenter delivery are separate from these read-only queries.

`GET /api/artifacts/approved` retains pagination for observed versions that currently pass policy. It is not an exhaustive list of versions covered by wildcard grants; assess exact candidate versions before use. The previous mirror routes remain read-only compatibility aliases during client upgrades; they no longer download or verify files.

## How to contribute

Report bugs and suggestions through the issue tracker. Create a fork and a feature branch, then submit a merge request for review.
