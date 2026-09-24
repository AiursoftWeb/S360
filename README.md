# S360 - Supply-chain control

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/AiursoftWeb/S360/blob/master/LICENSE)
[![Pipeline stat](https://gitlab.aiursoft.com/aiursoft/s360/badges/master/pipeline.svg)](https://gitlab.aiursoft.com/aiursoft/s360/-/pipelines)
[![Test Coverage](https://gitlab.aiursoft.com/aiursoft/s360/badges/master/coverage.svg)](https://gitlab.aiursoft.com/aiursoft/s360/-/pipelines)
[![Man hours](https://manhours.aiursoft.com/r/github.com/AiursoftWeb/S360.svg)](https://manhours.aiursoft.com/r/github.com/AiursoftWeb/S360.html)
[![Website](https://img.shields.io/badge/website-not%20deployed-lightgrey.svg)](#web-pilot-deployment)
[![Docker](https://img.shields.io/docker/pulls/aiursoft/s360.svg)](https://hub.docker.com/r/aiursoft/s360)

S360 is Aiursoft's supply-chain control center for NuGet and npm dependencies: employees request packages, administrators review the resolved dependency graph, and a single `s360 check` command evaluates build inputs against the current policy.

## Development status

This repository was created from Aiursoft Template. **Do not enable CI enforcement or deploy it as an approval authority yet.** It contains employee requests and dependency resolution, batch approvals, trust rules and an absolute blocklist, OSV synchronization and vulnerability audit pages, build check records, an AiurProtocol check endpoint, the `s360 check` CLI, and SQLite/MySQL migrations. GitLab enforcement has not been rolled out. The requirements document is currently a sibling workspace file, `../S360-开发需求文档.md`, and is not included in this repository.

The CLI requires `S360_SERVER` and `S360_CHECK_KEY`. Its `check --path .` command runs after `dotnet restore` and `npm ci`; missing artifacts, unsupported inputs, an unavailable S360 service, or any denied dependency produce a nonzero exit code. The API key authenticates a dedicated CI identity with `CanCheckDependencies`; a browser user's permission grant cannot replace that key. CI observations and server-side archive verification accept only sources configured in `SupplyChain:NuGetSources` or `SupplyChain:NpmSources`. A dependency from an unconfigured source is reported as a denied check decision with its name, version and source, but is not added to the artifact catalog or fetched by the vulnerability job. The scanner checks NuGet `.nupkg` and npm tarball identities inside their package manifests, as well as archive integrity evidence. It also requires every package reachable through mandatory npm lockfile edges to be installed, even if a tampered entry claims to be optional; genuinely optional absent packages are reported separately. For a denied dependency, the CLI prints an introduction chain reconstructed from NuGet restore or npm lock data; a NuGet package whose root cannot be identified is labelled as such instead of claiming a known direct parent. The check does not prove installed files were not changed by package scripts. Do not put the check key in source or logs. The Web resolver requires the .NET SDK and Node.js/npm at runtime and must be isolated from production secrets and unrelated files before production use. It rejects npm lockfiles whose tarball URLs leave the selected registry before running `npm ci`, and its own archive fetches do not follow redirects. This is not yet an egress sandbox for the npm and dotnet subprocesses: registry metadata and redirects during their resolution still need network-level controls before production use.

The GitLab pipeline and Docker build do not run S360 against this repository. The inherited Template pipeline still packs and publishes the CLI NuGet tool on master; publishing does not install it on a Runner or enable enforcement. Deployment of the Web service comes first; Runner installation and CI enforcement will be designed afterward. When that integration is discussed, the check key will be supplied through an environment variable, not a Docker secret.

On 2026-09-24, the inherited pipeline's local `Release` build and `pack --no-build` sequence produced `Aiursoft.S360.Client.1.0.1.nupkg`. Installing that package into a disposable tool path succeeded, and the installed `s360` exposed only the `check` subcommand. [Pipeline 65813](https://gitlab.aiursoft.com/aiursoft/s360/-/pipelines/65813) subsequently passed and published the CLI package and Docker image; it did not install the CLI on a Runner or deploy a running Web service.

## Web pilot deployment

The initial Web pilot needs a writable database and storage path, a .NET 10 SDK, Node.js/npm, access to the configured NuGet/npm mirrors, and access to OSV for vulnerability checks. Give the resolver a scratch volume with enough space for temporary package caches; set `TMPDIR` if the default `/tmp` is too small. An active package-name wildcard rule makes the periodic audit download OSV's full archive for that ecosystem so it can find advisories for packages never downloaded by S360. The npm archive was about 216 MB on 2026-09-24; allow for growth, download time, and temporary disk use. Archive failure leaves the previous audit findings in place and marks the new sync unsuccessful. Run the resolver in an isolated environment: it intentionally restores untrusted dependency metadata and archives, and subprocess network egress is not yet constrained by the application. Do not give this process production secrets unrelated to S360.

The intended deployment uses OIDC for staff identity. Keep the Template authentication defaults in source; configure `AppSettings__AuthProvider=OIDC`, `AppSettings__OIDC__Authority`, `AppSettings__OIDC__ClientId`, `AppSettings__OIDC__ClientSecret`, and the role-claim mapping through environment variables. Set `AppSettings__DefaultRole=Employees` only if every authenticated staff member should be able to submit requests. Set `SupplyChain__CheckApiKey` only when the check API is to be used; it remains blank for this Web-only stage. Configure each permitted mirror with an indexed array override, for example `SupplyChain__NuGetSources__0=https://nuget.aiursoft.com/v3/index.json` and `SupplyChain__NpmSources__0=https://npm.aiursoft.com` (then `__1`, `__2`, etc. for additional sources); an unindexed `SupplyChain__NuGetSources` string is not an array override. Grant employee/reviewer permissions through the application's role page. Keep the service's data and Data Protection keys persistent and back them up.

To validate locally, restore the application and run `dotnet test`; build frontend assets with `npm ci --prefix src/Aiursoft.S360/wwwroot` followed by `npm run build --prefix src/Aiursoft.S360/wwwroot`. A plain `dotnet publish` omits the ignored `wwwroot/node_modules` directory, so its output alone is **not** a complete manual deployment artifact: the inherited profile and settings pages still request Dropify CSS and JavaScript from that directory. The Dockerfile explicitly copies the slimmed frontend files into `/app/wwwroot`. A manual pilot must copy those built files into the publish output as well and verify the resulting URLs before deployment. CI has validated the multi-architecture container build, but not a running production service. Do not enable CI enforcement merely because a local Web build succeeds.

The Web app is based on Aiursoft Template. No downstream project is using S360 enforcement yet.

On 2026-09-24, a local Release `dotnet publish` succeeded. After copying the built `wwwroot/node_modules` files into that temporary publish directory as the Dockerfile does, the published application started with a disposable SQLite database; `/health`, `/`, and the Dropify CSS URL each returned HTTP 200. This verifies one manual publish/startup path, not a production OIDC deployment. Docker was unavailable to this workspace user; the separate CI image build and push succeeded.

A local OIDC-mode startup using environment overrides and a disposable SQLite database also returned HTTP 200 for `/health` and `/`; `/Dashboard` redirected to sign-in. The test used a deliberately nonexistent identity-provider address, so the actual OIDC challenge failed while fetching discovery metadata. This does not verify a real provider login. A solution-level Release `dotnet pack` produced `Aiursoft.S360.Client.1.0.1.nupkg`; installation from that local package into a temporary tool directory succeeded, and `s360 --help` exposed only `check`. No CLI was installed on a Runner, and the Template `.gitlab-ci.yml` remains unchanged.

On 2026-09-24, a controlled local smoke run invoked `PackageResolutionService.ResolveAsync` against the configured internal mirrors: `Newtonsoft.Json@13.0.3` resolved from NuGet and `is-odd@3.0.1` resolved from npm with its transitive `is-number` edge. The run verified 64-character SHA-256 values for the returned artifacts and passed without enabling CI enforcement. This checks one small real resolution path; it does not establish mirror availability, resolver isolation, or package safety in production.

A read-only scan of this repository on 2026-09-24 failed closed before contacting S360: the inherited Template `wwwroot/package-lock.json` lists `@aiursoft/uistack` as a root dependency, while `wwwroot/package.json` does not. Both files match the current Template copies. They have not been changed here to preserve Template symmetry; resolve the shared lockfile inconsistency before considering S360 self-enforcement. This does not affect the Web-only pilot or the existing CLI package publication.

`ninja all --path .` completed with exit code 0 on 2026-09-24. Its only suggestion was to replace “this s360” with “this template” in a `.gitlab-ci.yml` comment; that automatic edit was reverted because the pipeline file must remain untouched. Consequently this run is **not suggestion-free**. The Template frontend `npm ci` and `npm run build` both succeeded, with Dropify retained in the slimmed output. Local Docker socket access was unavailable; CI validated and published the image.

## Run in Ubuntu

The inherited Template installer and apt packaging have not been verified for this worktree. Do not use the commands below for a production S360 deployment without first validating the package and bootstrap configuration.

For now, use a controlled Web pilot from a locally verified complete artifact, including the frontend files described above; do not pipe an unverified installer into a privileged shell.

## Run manually

Local development prerequisites:

1. Install [.NET 10 SDK](http://dot.net/) and [Node.js](https://nodejs.org/).
2. Configure the Template authentication settings for your local environment.
3. Run `npm ci --prefix src/Aiursoft.S360/wwwroot` and `npm run build --prefix src/Aiursoft.S360/wwwroot`.
4. Run `dotnet run --project src/Aiursoft.S360`; use the URL printed by the host.

## Run in Microsoft Visual Studio

1. Open the `.sln` file in the project path.
2. Press `F5` to run the app.

## Run in Docker

First, install Docker [here](https://docs.docker.com/get-docker/).

The CI pipeline has published `aiursoft/s360`. Verify the image digest and application configuration in a controlled Web deployment before using it as an approval authority.

The repository Dockerfile produced the CI-published image, but a running deployment has not yet been verified:

| Properties  | Value                           |
|-------------|---------------------------------|
| Ports       | 5000                            |
| Binary path | /app                            |
| Data path   | /data                           |
| Config path | /data/appsettings.json          |

## How to contribute

There are many ways to contribute to the project: logging bugs, submitting pull requests, reporting issues, and creating suggestions.

Even if you with push rights on the repository, you should create a personal fork and create feature branches there when you need them. This keeps the main repository clean and your workflow cruft out of sight.

We're also interested in your feedback on the future of this project. You can submit a suggestion or feature request through the issue tracker. To make this process more effective, we're asking that these include more information to help define them more clearly.

## Configuration Guide

The defaults run as a standalone application with SQLite, local accounts, local file storage, and no ClickHouse server. Change a setting only after preparing the dependency named in its comment.

The Docker image copies this file to `/data/appsettings.json` on its first start and keeps that copy on later starts. Mount `/data` as a persistent volume. To override a value without editing the file, use an environment variable with double underscores, such as `Storage__Path` or `AppSettings__OIDC__ClientSecret`.

```jsonc
{
  "ConnectionStrings": {
    // True: cache EF Core query results in this process. False: read from the database on every query.
    "AllowCache": "True",

    // Sqlite: use a local database file and no database server. MySql: use an external MySQL server.
    // When changing this value, also replace DefaultConnection with a connection string for that provider.
    "DbType": "Sqlite",
    // With Sqlite, this creates app.db in the process working directory and applies migrations at startup.
    "DefaultConnection": "DataSource=app.db;Cache=Shared"

    // MySql requires a reachable server, database, user, and password. The application applies migrations at startup.
    // sudo docker run -d --name db -e MYSQL_RANDOM_ROOT_PASSWORD=true -e MYSQL_DATABASE=s360 -e MYSQL_USER=s360 -e MYSQL_PASSWORD=s360_password -p 3306:3306 hub.aiursoft.com/mysql
    //"DbType": "MySql",
    //"DefaultConnection": "Server=localhost;Database=s360;Uid=s360;Pwd=s360_password;"
  },
  "Storage": {
    // Writable local directory for public Workspace files and token-protected private Vault files.
    // This is not an S3 or MinIO bucket.
    // The Docker image changes /tmp/data to /data; mount /data as a persistent volume in production.
    "Path": "/tmp/data",

    // Optional second hostname for this application's own /download endpoints; this is not an S3 or MinIO URL.
    // Example: set https://files.example.com, point that DNS name to this server, and add this Caddy route:
    // files.example.com {
    //     reverse_proxy 127.0.0.1:5000
    // }
    // Replace 127.0.0.1:5000 with the same upstream used by the web UI. Leave empty to use the UI hostname.
    "PublicOrigin": "",

    // False: verified images and configured media can open on the normal web hostname.
    // True: inline viewing works only through PublicOrigin; the same request on the UI hostname downloads the file.
    // True requires PublicOrigin plus DNS, TLS, and a reverse-proxy route to this same application instance.
    "RequireDedicatedInlineOrigin": false,

    // False: only verified images and SafeInlineMediaExtensions open in the browser; every other file downloads.
    // True: every file type may open through PublicOrigin, and HTML or SVG scripts may run there.
    // True requires RequireDedicatedInlineOrigin=true and a PublicOrigin that receives no application cookies.
    "AllowArbitraryInlineOnDedicatedOrigin": false,

    // File extensions allowed to open after content-signature validation. Empty means no extra audio, video, or SVG.
    // Supported values are mp3, mp4, ogg, svg, wav, and webm. This does not grant upload permission.
    "SafeInlineMediaExtensions": [],

    // SVG opens only when svg is enabled above and its Workspace path starts with an entry in this list.
    // Example: [ "markdown-images" ]. Empty means every SVG downloads.
    "SafeInlineSvgSubfolders": [],

    // These values are copied into newly issued signed upload tokens; existing tokens keep their old policy.
    "UploadPolicy": {
      // False: a valid signed upload token is enough. True: the uploader must also be signed in to this application.
      "RequireAuthenticatedUser": false,

      // False: preserve spaces in uploaded file names. True: save each space as a hyphen.
      "ReplaceSpacesWithHyphens": false
    }
  },
  "AppSettings": {
    // Local: use built-in accounts and passwords. OIDC: redirect sign-in to an external identity provider.
    // OIDC also requires the OIDC section below and a provider callback URL of https://<web-host>/signin-oidc.
    "AuthProvider": "Local",

    // Empty: assign no automatic role. Otherwise, assign this role to every new local or OIDC user.
    // With Local, create the role first. With OIDC, the application creates it during account synchronization.
    "DefaultRole": "",

    // False: sign-in ends when the browser session closes. True: issue a persistent sign-in cookie.
    "PersistsSignIn": false,

    // This section is used only when AuthProvider is OIDC.
    "OIDC": {
      // Provider discovery base URL. It must be reachable by the application and should use HTTPS in production.
      "Authority": "https://auth.aiursoft.com/application/o/s360",
      // Client identifier created for this application in the OIDC provider.
      "ClientId": "",
      // Client secret created by the provider. Set AppSettings__OIDC__ClientSecret instead of committing a real secret.
      "ClientSecret": "",

      // Claim containing role names. On every login, local roles are replaced by these roles plus DefaultRole.
      "RolePropertyName": "groups",
      // Required claim used as the local username when an OIDC account is first created.
      "UsernamePropertyName": "preferred_username",
      // Required claim copied to the local display name on every login.
      "UserDisplayNamePropertyName": "name",
      // Required unique email claim. The provider must keep it verified, unique, and stable.
      "EmailPropertyName": "email",
      // Required immutable account identifier. Keep this mapped to the standard OIDC sub claim.
      "UserIdentityPropertyName": "sub"
    },

    // This section is used only when AuthProvider is Local.
    "Local": {
      // True: show self-registration and allow new local accounts. False: existing users can sign in, but cannot register.
      "AllowRegister": true,
      // True: require only six characters. False: require eight characters with upper, lower, digit, and symbol.
      "AllowWeakPassword": true
    }
  },
  "GlobalSettings": {
    // Leave an entry commented to use the database value or built-in default.
    // Uncommenting an entry forces that value and overrides changes made in the administration UI.

    // True: users may change their display nickname. False: only administrators control it.
    // "Allow_User_Adjust_Nickname": "True",
    // Text shown as the brand name in the footer.
    // "BrandName": "Aiursoft",
    // URL opened when a user clicks the footer brand name.
    // "BrandHomeUrl": "https://www.aiursoft.com/",
    // Mainland China ICP license number. Empty hides it.
    // "Icp": "",
    // Application name shown in the web interface.
    // "ProjectName": "Aiursoft S360"
  },
  "Logging": {
    "LogLevel": {
      // Minimum level for application logs. Typical values: Debug, Information, Warning, Error, or None.
      "Default": "Information",
      // Separate minimum level for ASP.NET Core framework logs; Warning reduces routine request noise.
      "Microsoft.AspNetCore": "Warning"
    },
    "Clickhouse": {
      // False: do not send logs to ClickHouse. True: create TableName at startup and send logs in batches.
      // Before enabling, provide a reachable ClickHouse server and valid credentials in ConnectionString.
      "Enabled": false,
      // ClickHouse host, protocol, port, credentials, and database. Used only when Enabled is true.
      "ConnectionString": "Host=localhost;Protocol=http;Port=8123;User=default;Password=;Database=AspNetCoreLogs",
      // ClickHouse table created and used for application logs when Enabled is true.
      "TableName": "S360Logs"
    }
  },
  // ASP.NET Core Host-header allowlist; this is not a CORS setting.
  // * accepts every hostname. In production, use semicolon-separated names such as example.com;www.example.com.
  "AllowedHosts": "*"
}
```
