using System.Buffers;
using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Aiursoft.S360.SDK;

public static class DependencyScanner
{
    public static async Task<List<Dependency>> ScanAsync(string root, HttpClient http, CancellationToken cancellationToken = default) =>
        (await ScanDetailedAsync(root, http, cancellationToken)).Dependencies;

    public static async Task<ScanReport> ScanDetailedAsync(string root, HttpClient http,
        CancellationToken cancellationToken = default, string? expectedNpmSource = null)
    {
        if (!Directory.Exists(root)) throw new DirectoryNotFoundException(root);
        var result = new List<Dependency>();
        var skipped = new List<string>();
        var projectFiles = DiscoverProjectFiles(root).ToList();
        var manifests = projectFiles.Where(p => Path.GetExtension(p) is ".csproj" or ".fsproj" or ".vbproj").ToList();
        var npmComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        var npmManifests = projectFiles.Where(p => Path.GetFileName(p).Equals("package.json", npmComparison)).ToList();
        if (manifests.Count == 0 && npmManifests.Count == 0)
            throw new InvalidOperationException("No supported NuGet or npm project was found.");
        var introductionPaths = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        var discoveredProjects = manifests.Select(Path.GetFullPath).ToHashSet(
            OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var manifest in manifests)
        {
            var folder = Path.GetDirectoryName(manifest)!;
            if (File.Exists(Path.Combine(folder, "packages.config")))
                throw new InvalidOperationException($"NuGet packages.config projects are not supported: {manifest}");
            var assets = Path.Combine(folder, "obj", "project.assets.json");
            if (!File.Exists(assets)) throw new InvalidOperationException($"Missing restore output: {assets}");
            ValidateNuGetAssetsForProject(manifest, assets);
            ValidateNuGetProjectReferences(manifest, assets, discoveredProjects);
            var restored = await ReadNuGetAsync(assets, cancellationToken);
            DependencyIntroductionPaths.AddNuGet(assets, restored, Path.GetRelativePath(root, manifest), introductionPaths);
            result.AddRange(restored);
        }
        foreach (var manifest in npmManifests)
        {
            var folder = Path.GetDirectoryName(manifest)!;
            // npm 11 uses shrinkwrap in preference to package-lock when both exist.
            var shrinkwrap = Path.Combine(folder, "npm-shrinkwrap.json");
            var lockFile = File.Exists(shrinkwrap) ? shrinkwrap : Path.Combine(folder, "package-lock.json");
            if (!File.Exists(lockFile)) throw new InvalidOperationException($"Missing npm lockfile: {lockFile}");
            await ValidateNpmManifestLockAsync(manifest, lockFile, cancellationToken);
            var installed = await ReadNpmAsync(lockFile, folder, http, cancellationToken, skipped, expectedNpmSource);
            DependencyIntroductionPaths.AddNpm(lockFile, installed, Path.GetRelativePath(root, manifest), introductionPaths);
            if (installed.Any(dependency => !introductionPaths.ContainsKey(DependencyIntroductionPaths.Identity(dependency))))
                throw new InvalidOperationException($"npm installation graph has an installed package with no introduction path: {manifest}");
            result.AddRange(installed);
        }
        return new ScanReport(result.DistinctBy(DependencyIntroductionPaths.Identity).ToList(),
            skipped, manifests.Count + npmManifests.Count) { IntroductionPaths = introductionPaths };
    }

    private static IEnumerable<string> DiscoverProjectFiles(string root)
    {
        var pending = new Stack<string>();
        var npmComparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        pending.Push(root);
        while (pending.TryPop(out var directory))
        {
            foreach (var file in Directory.EnumerateFiles(directory))
            {
                if (Path.GetExtension(file) is ".csproj" or ".fsproj" or ".vbproj" ||
                    Path.GetFileName(file).Equals("package.json", npmComparison))
                    yield return file;
            }
            foreach (var child in Directory.EnumerateDirectories(directory))
            {
                if (Path.GetFileName(child) is "node_modules" or "bin" or "obj" or ".git" or "TestResults")
                    continue;
                if ((File.GetAttributes(child) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException($"Directory links cannot be scanned completely: {child}");
                pending.Push(child);
            }
        }
    }

    public static void ValidateNuGetAssetsForProject(string manifestPath, string assetsPath)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(assetsPath));
        if (!doc.RootElement.TryGetProperty("project", out var project) ||
            !project.TryGetProperty("restore", out var restore) ||
            !restore.TryGetProperty("projectPath", out var recordedPath) ||
            recordedPath.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(recordedPath.GetString()) ||
            !Path.IsPathFullyQualified(recordedPath.GetString()!) ||
            !Path.GetFullPath(recordedPath.GetString()!).Equals(Path.GetFullPath(manifestPath),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            throw new InvalidOperationException($"NuGet restore output does not belong to this project: {manifestPath}");

        var restoredAtUtc = File.GetLastWriteTimeUtc(assetsPath);
        if (File.GetLastWriteTimeUtc(manifestPath) > restoredAtUtc)
            throw new InvalidOperationException($"NuGet project changed after restore: {manifestPath}");
        var directory = Path.GetDirectoryName(Path.GetFullPath(manifestPath));
        while (directory != null)
        {
            foreach (var fileName in new[] { "Directory.Packages.props", "Directory.Build.props", "Directory.Build.targets" })
            {
                var input = Path.Combine(directory, fileName);
                if (File.Exists(input) && File.GetLastWriteTimeUtc(input) > restoredAtUtc)
                    throw new InvalidOperationException($"NuGet restore input changed after restore: {input}");
            }
            directory = Directory.GetParent(directory)?.FullName;
        }
    }

    public static void ValidateNuGetProjectReferences(string manifestPath, string assetsPath,
        IReadOnlySet<string> discoveredProjects)
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(assetsPath));
        if (!doc.RootElement.TryGetProperty("libraries", out var libraries) ||
            libraries.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException($"NuGet restore libraries are missing: {assetsPath}");
        var projectFolder = Path.GetDirectoryName(Path.GetFullPath(manifestPath))!;
        foreach (var library in libraries.EnumerateObject())
        {
            if (!library.Value.TryGetProperty("type", out var type) || type.GetString() != "project") continue;
            if (!library.Value.TryGetProperty("msbuildProject", out var reference) ||
                reference.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(reference.GetString()))
                throw new InvalidOperationException($"NuGet project reference has no project path: {library.Name}");
            var referencedPath = Path.GetFullPath(Path.Combine(projectFolder, reference.GetString()!));
            if (!discoveredProjects.Contains(referencedPath))
                throw new InvalidOperationException($"NuGet project reference is outside the scanned projects: " +
                    $"{referencedPath}. Scan a directory containing both projects.");
        }
    }

    public static async Task ValidateNpmManifestLockAsync(string manifestPath, string lockPath,
        CancellationToken cancellationToken = default)
    {
        using var manifest = JsonDocument.Parse(await File.ReadAllTextAsync(manifestPath, cancellationToken));
        using var locked = JsonDocument.Parse(await File.ReadAllTextAsync(lockPath, cancellationToken));
        if (!locked.RootElement.TryGetProperty("packages", out var packages) ||
            !packages.TryGetProperty("", out var root))
            throw new InvalidOperationException($"npm lockfile root package is missing: {lockPath}");
        foreach (var group in new[] { "dependencies", "devDependencies", "optionalDependencies", "peerDependencies" })
        {
            var declared = ReadDependencyGroup(manifest.RootElement, group);
            var recorded = ReadDependencyGroup(root, group);
            if (declared.Count != recorded.Count ||
                declared.Any(pair => !recorded.TryGetValue(pair.Key, out var value) || value != pair.Value))
                throw new InvalidOperationException($"npm {group} differs between package.json and the active lockfile: {lockPath}");
        }
    }

    private static Dictionary<string, string> ReadDependencyGroup(JsonElement value, string group)
    {
        if (!value.TryGetProperty(group, out var entries)) return new Dictionary<string, string>(StringComparer.Ordinal);
        if (entries.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException($"npm {group} must be an object.");
        return entries.EnumerateObject().ToDictionary(entry => entry.Name,
            entry => entry.Value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(entry.Value.GetString())
                ? entry.Value.GetString()!
                : throw new InvalidOperationException($"npm {group} contains an invalid dependency specifier: {entry.Name}"),
            StringComparer.Ordinal);
    }

    public static async Task ValidateNpmArchiveSourcesAsync(string lockPath, string expectedSource,
        CancellationToken cancellationToken = default)
    {
        var normalizedSource = TrustPattern.NormalizeSource(expectedSource);
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(lockPath, cancellationToken));
        if (!document.RootElement.TryGetProperty("lockfileVersion", out var version) ||
            version.GetInt32() is not (2 or 3) ||
            !document.RootElement.TryGetProperty("packages", out var packages) ||
            packages.ValueKind != JsonValueKind.Object)
            throw new InvalidOperationException($"Only npm lockfile v2/v3 is supported: {lockPath}");
        foreach (var item in packages.EnumerateObject().Where(p => p.Name != ""))
        {
            ValidateNpmPackagePath(item.Name);
            if (item.Value.TryGetProperty("link", out var link) && link.ValueKind == JsonValueKind.True)
                throw new InvalidOperationException($"npm symlink package is unsupported: {item.Name}");
            var url = RequiredString(item.Value, "resolved", item.Name);
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
                !string.Equals(TrustPattern.NormalizeSource(uri.GetLeftPart(UriPartial.Authority)),
                    normalizedSource, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"npm archive source is outside the selected registry: {item.Name}");
        }
    }

    public static async Task<List<Dependency>> ReadNuGetAsync(string assetsPath, CancellationToken cancellationToken = default)
    {
        using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(assetsPath, cancellationToken));
        var root = doc.RootElement;
        if (!root.TryGetProperty("targets", out var targets) || targets.EnumerateObject().Any() == false)
            throw new InvalidOperationException($"No restored targets in {assetsPath}");
        var folders = root.GetProperty("packageFolders").EnumerateObject().Select(p => p.Name).ToList();
        var found = new Dictionary<string, Dependency>(StringComparer.OrdinalIgnoreCase);
        foreach (var target in targets.EnumerateObject())
        foreach (var item in target.Value.EnumerateObject())
        {
            if (item.Value.GetProperty("type").GetString() != "package") continue;
            var slash = item.Name.LastIndexOf('/');
            if (slash < 1) throw new InvalidOperationException($"Unrecognized NuGet package: {item.Name}");
            var name = item.Name[..slash];
            var version = item.Name[(slash + 1)..];
            if (!SafeNuGetPathComponent(name) || !SafeNuGetPathComponent(version))
                throw new InvalidOperationException($"Unsafe NuGet package identity in restore output: {item.Name}");
            var key = $"{name.ToLowerInvariant()}/{version}";
            if (found.ContainsKey(key)) continue;
            var packagePath = folders.Select(f => Path.Combine(f, name.ToLowerInvariant(), version.ToLowerInvariant()))
                .FirstOrDefault(Directory.Exists) ?? throw new InvalidOperationException($"Package cache missing: {item.Name}");
            var archive = Path.Combine(packagePath, $"{name.ToLowerInvariant()}.{version.ToLowerInvariant()}.nupkg");
            var metadata = Path.Combine(packagePath, ".nupkg.metadata");
            var sha512File = Path.Combine(packagePath, $"{name.ToLowerInvariant()}.{version.ToLowerInvariant()}.nupkg.sha512");
            if (!File.Exists(archive) || !File.Exists(metadata) || !File.Exists(sha512File))
                throw new InvalidOperationException($"Package archive or restore evidence missing: {item.Name}");
            using var meta = JsonDocument.Parse(await File.ReadAllTextAsync(metadata, cancellationToken));
            if (!meta.RootElement.TryGetProperty("source", out var sourceElement))
                throw new InvalidOperationException($"NuGet package source missing: {item.Name}");
            var source = TrustPattern.NormalizeSource(sourceElement.GetString() ?? "");
            // NuGet's contentHash excludes package signature metadata, while the
            // .nupkg.sha512 sidecar hashes the exact archive bytes. A signed package
            // can legitimately have different values for these two SHA-512 hashes.
            var archiveSha512 = (await File.ReadAllTextAsync(sha512File, cancellationToken)).Trim();
            if (!root.TryGetProperty("libraries", out var libraries) ||
                !libraries.TryGetProperty(item.Name, out var library) ||
                !library.TryGetProperty("sha512", out var libraryHash) ||
                !meta.RootElement.TryGetProperty("contentHash", out var restoredHash) ||
                libraryHash.GetString() != restoredHash.GetString())
                throw new InvalidOperationException($"NuGet restore hash evidence is inconsistent: {item.Name}");
            await using var stream = File.OpenRead(archive);
            var actual512 = Convert.ToBase64String(await SHA512.HashDataAsync(stream, cancellationToken));
            if (!CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(archiveSha512),
                    Convert.FromBase64String(actual512)))
                throw new InvalidOperationException($"NuGet archive integrity mismatch: {item.Name}");
            stream.Position = 0;
            ValidateNuGetArchiveIdentity(stream, name, version, item.Name);
            stream.Position = 0;
            var sha256 = Convert.ToHexStringLower(await SHA256.HashDataAsync(stream, cancellationToken));
            found.Add(key, new Dependency { Ecosystem = "nuget", Name = name, Version = version, Source = source, Sha256 = sha256 });
        }
        return found.Values.ToList();
    }

    private static bool SafeNuGetPathComponent(string value) =>
        !string.IsNullOrWhiteSpace(value) && value is not ("." or "..") &&
        !value.Any(character => character is '/' or '\\' or ':' || char.IsControl(character));

    private static void ValidateNuGetArchiveIdentity(Stream archive, string name, string version, string packageKey)
    {
        try
        {
            using var zip = new ZipArchive(archive, ZipArchiveMode.Read, leaveOpen: true);
            var manifests = zip.Entries.Where(entry =>
                !entry.FullName.Contains('/') && entry.FullName.EndsWith(".nuspec", StringComparison.OrdinalIgnoreCase)).ToList();
            if (manifests.Count != 1 || manifests[0].Length > 1024 * 1024)
                throw new InvalidOperationException($"NuGet archive must contain one root nuspec manifest: {packageKey}");
            using var contents = manifests[0].Open();
            using var reader = XmlReader.Create(contents, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null
            });
            var document = XDocument.Load(reader);
            var metadata = document.Root?.Name.LocalName == "package"
                ? document.Root.Elements().SingleOrDefault(element => element.Name.LocalName == "metadata")
                : null;
            var archiveName = metadata?.Elements().SingleOrDefault(element => element.Name.LocalName == "id")?.Value;
            var archiveVersion = metadata?.Elements().SingleOrDefault(element => element.Name.LocalName == "version")?.Value;
            if (!string.Equals(archiveName, name, StringComparison.OrdinalIgnoreCase) ||
                !NuGetVersionsMatch(archiveVersion, version))
                throw new InvalidOperationException($"NuGet archive identity differs from restore output: {packageKey}");
        }
        catch (Exception exception) when (exception is InvalidDataException or XmlException)
        {
            throw new InvalidOperationException($"Invalid NuGet archive: {packageKey}", exception);
        }
    }

    private static bool NuGetVersionsMatch(string? archiveVersion, string restoredVersion)
    {
        static (Version? Numeric, string Prerelease) Parse(string? input)
        {
            if (string.IsNullOrWhiteSpace(input)) return (null, "");
            var withoutMetadata = input.Split('+', 2)[0];
            var dash = withoutMetadata.IndexOf('-');
            var numeric = dash < 0 ? withoutMetadata : withoutMetadata[..dash];
            var prerelease = dash < 0 ? "" : withoutMetadata[dash..];
            var parts = numeric.Split('.');
            if (parts.Length is < 2 or > 4 || parts.Any(part => !int.TryParse(part, out var value) || value < 0))
                return (null, "");
            if (parts.Length == 2) numeric += ".0";
            if (!Version.TryParse(numeric, out var parsed)) return (null, "");
            return (new Version(parsed.Major, parsed.Minor, parsed.Build,
                parsed.Revision < 0 ? 0 : parsed.Revision), prerelease);
        }

        var first = Parse(archiveVersion);
        var second = Parse(restoredVersion);
        return first.Numeric != null && first.Numeric == second.Numeric &&
            string.Equals(first.Prerelease, second.Prerelease, StringComparison.OrdinalIgnoreCase);
    }

    public static async Task<List<Dependency>> ReadNpmAsync(string lockPath, string projectPath, HttpClient http,
        CancellationToken cancellationToken = default, ICollection<string>? skippedOptional = null,
        string? expectedSource = null)
    {
        if (expectedSource != null)
            await ValidateNpmArchiveSourcesAsync(lockPath, expectedSource, cancellationToken);
        using var doc = JsonDocument.Parse(await File.ReadAllTextAsync(lockPath, cancellationToken));
        var root = doc.RootElement;
        if (!root.TryGetProperty("lockfileVersion", out var lockVersion) || lockVersion.GetInt32() is not (2 or 3) ||
            !root.TryGetProperty("packages", out var packages))
            throw new InvalidOperationException($"Only npm lockfile v2/v3 is supported: {lockPath}");
        ValidateRequiredNpmInstallations(packages, projectPath);
        var lockedPaths = packages.EnumerateObject().Where(item => item.Name != "")
            .Select(item => item.Name).ToHashSet(StringComparer.Ordinal);
        foreach (var installedPath in EnumerateInstalledNpmPackages(projectPath))
            if (!lockedPaths.Contains(installedPath))
                throw new InvalidOperationException($"Installed npm package is absent from the lockfile: {installedPath}");
        var found = new List<Dependency>();
        foreach (var item in packages.EnumerateObject())
        {
            if (item.Name == "") continue;
            ValidateNpmPackagePath(item.Name);
            var entry = item.Value;
            if (entry.TryGetProperty("link", out var linked) && linked.GetBoolean())
                throw new InvalidOperationException($"npm symlink package is unsupported: {item.Name}");
            var installationName = item.Name[(item.Name.LastIndexOf("node_modules/", StringComparison.Ordinal) + 13)..];
            if (installationName.Contains("node_modules/", StringComparison.Ordinal))
                throw new InvalidOperationException($"Invalid npm package path: {item.Name}");
            var name = entry.TryGetProperty("name", out var declaredName) && declaredName.ValueKind == JsonValueKind.String
                ? declaredName.GetString()! : installationName;
            var version = RequiredString(entry, "version", item.Name);
            var url = RequiredString(entry, "resolved", item.Name);
            var integrity = RequiredString(entry, "integrity", item.Name);
            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps ||
                !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment))
                throw new InvalidOperationException($"Unsupported npm archive URL: {item.Name}");
            var separator = integrity.IndexOf('-');
            if (separator < 1 || separator == integrity.Length - 1 || integrity.Contains(' '))
                throw new InvalidOperationException($"Unsupported npm integrity: {item.Name}");
            var algorithm = integrity[..separator];
            if (algorithm is not ("sha512" or "sha256"))
                throw new InvalidOperationException($"Unsupported npm integrity algorithm: {item.Name}");
            var expected = Convert.FromBase64String(integrity[(separator + 1)..]);
            // npm install/ci must already have completed. This detects missing installation;
            // archive integrity is separately checked against the lockfile below.
            var installedPath = Path.Combine(projectPath, item.Name.Replace('/', Path.DirectorySeparatorChar));
            if (!Directory.Exists(installedPath))
            {
                if (entry.TryGetProperty("optional", out var optional) && optional.ValueKind == JsonValueKind.True)
                {
                    skippedOptional?.Add($"{name}@{version}: optional package is not installed on this platform");
                    continue;
                }
                throw new InvalidOperationException($"npm package is not installed: {item.Name}");
            }
            var installedManifest = Path.Combine(installedPath, "package.json");
            if (!File.Exists(installedManifest))
                throw new InvalidOperationException($"Installed npm package manifest is missing: {item.Name}");
            using (var installed = JsonDocument.Parse(await File.ReadAllTextAsync(installedManifest, cancellationToken)))
            {
                if (RequiredString(installed.RootElement, "name", item.Name) != name ||
                    RequiredString(installed.RootElement, "version", item.Name) != version)
                    throw new InvalidOperationException($"Installed npm package identity differs from the lockfile: {item.Name}");
            }
            using var response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            response.EnsureSuccessStatusCode();
            var responseUri = response.RequestMessage?.RequestUri ?? uri;
            if (responseUri.Scheme != Uri.UriSchemeHttps ||
                !string.Equals(responseUri.GetLeftPart(UriPartial.Authority), uri.GetLeftPart(UriPartial.Authority),
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException($"npm archive was served from a different source: {item.Name}");
            if (response.Content.Headers.ContentLength > 512L * 1024 * 1024)
                throw new InvalidOperationException($"npm archive exceeds 512 MiB: {item.Name}");
            await using var archive = await response.Content.ReadAsStreamAsync(cancellationToken);
            await using var savedArchive = new FileStream(
                Path.Combine(Path.GetTempPath(), "s360-npm-" + Guid.NewGuid().ToString("N")),
                FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 64 * 1024,
                FileOptions.Asynchronous | FileOptions.DeleteOnClose);
            using var integrityHash = IncrementalHash.CreateHash(algorithm == "sha512" ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256);
            using var packageHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
            try
            {
                long size = 0;
                int read;
                while ((read = await archive.ReadAsync(buffer, cancellationToken)) != 0)
                {
                    size += read;
                    if (size > 512L * 1024 * 1024)
                        throw new InvalidOperationException($"npm archive exceeds 512 MiB: {item.Name}");
                    integrityHash.AppendData(buffer, 0, read);
                    packageHash.AppendData(buffer, 0, read);
                    await savedArchive.WriteAsync(buffer.AsMemory(0, read), cancellationToken);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
            var actual = integrityHash.GetHashAndReset();
            if (!CryptographicOperations.FixedTimeEquals(expected, actual))
                throw new InvalidOperationException($"npm archive integrity mismatch: {item.Name}");
            savedArchive.Position = 0;
            await ValidateNpmArchiveIdentityAsync(savedArchive, name, version, item.Name, cancellationToken);
            found.Add(new Dependency
            {
                Ecosystem = "npm", Name = name, Version = version,
                Source = TrustPattern.NormalizeSource(uri.GetLeftPart(UriPartial.Authority)),
                Sha256 = Convert.ToHexStringLower(packageHash.GetHashAndReset())
            });
        }
        return found;
    }

    private static async Task ValidateNpmArchiveIdentityAsync(Stream archive, string name, string version,
        string packagePath, CancellationToken cancellationToken)
    {
        try
        {
            using var gzip = new GZipStream(archive, CompressionMode.Decompress, leaveOpen: true);
            using var tar = new TarReader(gzip, leaveOpen: true);
            var found = false;
            TarEntry? entry;
            while ((entry = await tar.GetNextEntryAsync(cancellationToken: cancellationToken)) != null)
            {
                if (entry.Name != "package/package.json") continue;
                if (found || entry.EntryType != TarEntryType.RegularFile || entry.DataStream == null ||
                    entry.Length > 1024 * 1024)
                    throw new InvalidOperationException($"Invalid npm archive package manifest: {packagePath}");
                found = true;
                using var manifest = await JsonDocument.ParseAsync(entry.DataStream, cancellationToken: cancellationToken);
                if (RequiredString(manifest.RootElement, "name", packagePath) != name ||
                    RequiredString(manifest.RootElement, "version", packagePath) != version)
                    throw new InvalidOperationException($"npm archive identity differs from the lockfile: {packagePath}");
            }
            if (!found)
                throw new InvalidOperationException($"npm archive package manifest is missing: {packagePath}");
        }
        catch (Exception exception) when (exception is InvalidDataException or JsonException)
        {
            throw new InvalidOperationException($"Invalid npm archive: {packagePath}", exception);
        }
    }

    private static void ValidateNpmPackagePath(string packagePath)
    {
        // The lockfile's package key becomes a physical path below projectPath.
        // Reject traversal and platform-specific separators before combining it.
        if (packagePath.Contains('\\') || packagePath.Contains(':') ||
            !packagePath.StartsWith("node_modules/", StringComparison.Ordinal) ||
            packagePath.Split('/').Any(segment => segment is "" or "." or ".."))
            throw new InvalidOperationException($"Unsupported npm workspace/local package path: {packagePath}");
    }

    private static void ValidateRequiredNpmInstallations(JsonElement packages, string projectPath)
    {
        if (packages.ValueKind != JsonValueKind.Object || !packages.TryGetProperty("", out _))
            throw new InvalidOperationException("npm lockfile root package is missing.");
        var locked = packages.EnumerateObject().ToDictionary(item => item.Name, item => item.Value,
            StringComparer.Ordinal);
        var pending = new Queue<string>();
        var required = new HashSet<string>(StringComparer.Ordinal);
        pending.Enqueue("");
        while (pending.TryDequeue(out var path))
        {
            if (!required.Add(path)) continue;
            var package = locked[path];
            var groups = path == ""
                ? new[] { "dependencies", "devDependencies", "peerDependencies" }
                : ["dependencies", "peerDependencies"];
            foreach (var group in groups)
            foreach (var name in ReadDependencyGroup(package, group).Keys)
            {
                if (group == "peerDependencies" &&
                    package.TryGetProperty("peerDependenciesMeta", out var metadata) &&
                    metadata.ValueKind == JsonValueKind.Object &&
                    metadata.TryGetProperty(name, out var peer) &&
                    peer.ValueKind == JsonValueKind.Object &&
                    peer.TryGetProperty("optional", out var optional) && optional.ValueKind == JsonValueKind.True)
                    continue;
                var child = ResolveNpmLockPath(path, name, locked);
                if (child == null)
                    throw new InvalidOperationException($"Required npm dependency is missing from the lockfile: {path} -> {name}");
                pending.Enqueue(child);
            }
        }
        foreach (var path in required.Where(path => path != ""))
        {
            ValidateNpmPackagePath(path);
            var installed = Path.Combine(projectPath, path.Replace('/', Path.DirectorySeparatorChar));
            if (!Directory.Exists(installed))
                throw new InvalidOperationException($"Required npm dependency is not installed: {path}");
        }
    }

    private static string? ResolveNpmLockPath(string parentPath, string name,
        IReadOnlyDictionary<string, JsonElement> locked)
    {
        var prefix = parentPath;
        while (true)
        {
            var candidate = prefix.Length == 0 ? $"node_modules/{name}" : $"{prefix}/node_modules/{name}";
            if (locked.ContainsKey(candidate)) return candidate;
            var separator = prefix.LastIndexOf("/node_modules/", StringComparison.Ordinal);
            if (separator < 0)
            {
                if (prefix.Length == 0) return null;
                prefix = "";
            }
            else prefix = prefix[..separator];
        }
    }

    private static IEnumerable<string> EnumerateInstalledNpmPackages(string projectPath)
    {
        var pending = new Stack<string>();
        pending.Push(projectPath);
        while (pending.TryPop(out var parent))
        {
            var modules = Path.Combine(parent, "node_modules");
            if (!Directory.Exists(modules)) continue;
            RejectNpmDirectoryLink(modules);
            foreach (var child in Directory.EnumerateDirectories(modules))
            {
                RejectNpmDirectoryLink(child);
                var name = Path.GetFileName(child);
                if (name.StartsWith(".", StringComparison.Ordinal)) continue;
                var packageDirectories = name.StartsWith("@", StringComparison.Ordinal)
                    ? Directory.EnumerateDirectories(child)
                    : new[] { child };
                foreach (var packageDirectory in packageDirectories)
                {
                    RejectNpmDirectoryLink(packageDirectory);
                    if (!File.Exists(Path.Combine(packageDirectory, "package.json")))
                        throw new InvalidOperationException($"Installed npm package manifest is missing: {packageDirectory}");
                    yield return Path.GetRelativePath(projectPath, packageDirectory)
                        .Replace(Path.DirectorySeparatorChar, '/');
                    pending.Push(packageDirectory);
                }
            }
        }
    }

    private static void RejectNpmDirectoryLink(string path)
    {
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException($"npm symlink package directory is unsupported: {path}");
    }

    private static string RequiredString(JsonElement entry, string property, string name) =>
        entry.TryGetProperty(property, out var value) && !string.IsNullOrWhiteSpace(value.GetString())
            ? value.GetString()!
            : throw new InvalidOperationException($"npm {property} missing for {name}");
}

public record ScanReport(List<Dependency> Dependencies, List<string> SkippedOptional, int ScannedProjectCount)
{
    public Dictionary<string, List<string>> IntroductionPaths { get; init; } = new(StringComparer.Ordinal);

    public IReadOnlyList<string> PathsFor(Dependency dependency) =>
        IntroductionPaths.TryGetValue(DependencyIntroductionPaths.Identity(dependency), out var paths)
            ? paths : [];
}
