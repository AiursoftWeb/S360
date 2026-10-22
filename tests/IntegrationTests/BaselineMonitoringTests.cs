using System.Net;
using System.Text.Json;
using Aiursoft.AlertCenter.SDK.Models;
using Aiursoft.AiurProtocol.Models;
using Aiursoft.AiurProtocol.Services;
using Aiursoft.S360.Configuration;
using Aiursoft.S360.Entities;
using Aiursoft.S360.InMemory;
using Aiursoft.S360.SDK;
using Aiursoft.S360.Services;
using Aiursoft.S360.Services.AlertMonitoring;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Newtonsoft.Json.Linq;

namespace Aiursoft.S360.Tests.IntegrationTests;

[TestClass]
public class BaselineMonitoringTests : TestBase
{
    private readonly string _repository = "aiursoft/monitor-" + Guid.NewGuid().ToString("N");
    private readonly InMemoryContext _db = new(new DbContextOptionsBuilder<InMemoryContext>()
        .UseInMemoryDatabase("baseline-monitoring-" + Guid.NewGuid()).Options);

    [TestCleanup]
    public override async Task CleanServer()
    {
        if (Server != null)
        {
            using var scope = Server.Services.CreateScope();
            await scope.ServiceProvider.GetRequiredService<GlobalSettingsService>()
                .UpdateSettingAsync(SettingsMap.AlertCenterEnabled, "False");
        }
        await _db.DisposeAsync();
        await base.CleanServer();
    }

    private const string PackageSource = "https://nuget.aiursoft.com/v3/index.json";

    private static BuildCheck Report(string project, bool clean, string purpose = "baseline", int batches = 1,
        string pipelineSource = "push") => new()
    {
        Project = project, RunId = Guid.NewGuid().ToString("N"), ScannedProjectCount = 1, BatchCount = batches,
        ContextJson = JsonSerializer.Serialize(new CheckContext
        {
            Purpose = purpose, Ecosystem = "nuget", Provider = "gitlab", Ref = "master", DefaultBranch = "master",
            PipelineSource = pipelineSource
        }),
        Trusted = clean, Commit = "commit", Pipeline = "https://gitlab.aiursoft.com/aiursoft/test/-/pipelines/1",
        Dependencies = clean ? [] : [new BuildCheckDependency
        {
            BuildCheckId = 0, PackageArtifactId = null, Name = "Unapproved.Package", Version = "1.0.0",
            Ecosystem = "nuget", Source = PackageSource, Sha256 = new string('a', 64), Trusted = false
        }]
    };

    private async Task<BaselineMonitoringService> Monitor(IServiceScope scope, FakeClient client, BaselineMonitorState state,
        bool enabled = true, bool autoMitigate = true)
    {
        var settings = scope.ServiceProvider.GetRequiredService<GlobalSettingsService>();
        await settings.UpdateSettingAsync(SettingsMap.AlertCenterEnabled, enabled.ToString());
        await settings.UpdateSettingAsync(SettingsMap.AlertCenterAutoMitigate, autoMitigate.ToString());
        await settings.UpdateSettingAsync(SettingsMap.AlertCenterApiKey, "isolated-test-key");
        await settings.UpdateSettingAsync(SettingsMap.AlertCenterEndpoint, "http://localhost:1");
        return new BaselineMonitoringService(_db,
            new CatalogInventoryService(_db, new TrustService(_db), scope.ServiceProvider.GetRequiredService<IConfiguration>()), new AlertCenterSettingsProvider(settings),
            client, state, NullLogger<BaselineMonitoringService>.Instance);
    }

    private static void FreshAudit(TemplateDbContext db, bool stale = false, bool failed = false)
    {
        db.VulnerabilitySyncStates.Add(new VulnerabilitySyncState
        {
            LastAttemptAtUtc = failed ? DateTime.UtcNow : DateTime.UtcNow.AddMinutes(-2), LastSuccessfulAttemptAtUtc = DateTime.UtcNow.AddMinutes(-2),
            LastSuccessAtUtc = DateTime.UtcNow.AddMinutes(-1).AddHours(stale ? -13 : 0),
            LastError = failed ? "Unavailable" : null
        });
    }

    [TestMethod]
    public async Task KnownFindingCreatesSev2AndRepeatedRunsOrProcessorRestartsDoNotDuplicate()
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        db.BuildChecks.Add(Report(_repository, false));
        await db.SaveChangesAsync();
        var client = new FakeClient();
        var state = new BaselineMonitorState();
        for (var i = 0; i < 3; i++) await (await Monitor(scope, client, state)).SynchronizeAsync();
        Assert.HasCount(1, client.Created);
        Assert.AreEqual("sev2", client.Created[0].Level);
        Assert.Contains("Unapproved.Package@1.0.0", client.Created[0].Content!);
        Assert.Contains("entire pipeline succeeds", client.Created[0].Content!);
        Assert.AreEqual(BaselineMonitoringService.Source, client.Created[0].Metadata!.Value<string>("source"));
        Assert.IsTrue(state.LastRun!.Succeeded);
    }

    [TestMethod]
    public async Task NewlyDisclosedCveUsesExistingBaselineWithoutAnotherBuild()
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        FreshAudit(db);
        var artifact = new PackageArtifact
        {
            Ecosystem = "nuget", Name = "Approved.Package", Version = "1.0.0", Source = PackageSource,
            Sha256 = new string('b', 64), SourceVerifiedAtUtc = DateTime.UtcNow.AddHours(-1),
            FirstTrustedAtUtc = DateTime.UtcNow.AddHours(-1), LastCheckedAtUtc = DateTime.UtcNow.AddSeconds(-90)
        };
        db.TrustRules.Add(new TrustRule
        {
            SupplierId = 0, ApplicationId = null, Supplier = new Supplier { Name = "Test supplier" }, Ecosystem = "nuget", Source = PackageSource,
            PackagePattern = artifact.Name, Version = "1.*", Status = TrustRuleStatus.Approved
        });
        var report = Report(_repository, true);
        report = new BuildCheck
        {
            Project = report.Project, RunId = report.RunId, ScannedProjectCount = report.ScannedProjectCount,
            ContextJson = report.ContextJson, Trusted = true, Dependencies = [new BuildCheckDependency
        {
            BuildCheckId = 0, PackageArtifactId = 0, PackageArtifact = artifact, Ecosystem = "nuget",
            Name = artifact.Name, Version = artifact.Version, Source = PackageSource, Sha256 = artifact.Sha256, Trusted = true
        }]
        };
        db.BuildChecks.Add(report);
        await db.SaveChangesAsync();
        var client = new FakeClient();
        var state = new BaselineMonitorState();
        var monitoring = await Monitor(scope, client, state);
        await monitoring.SynchronizeAsync();
        Assert.HasCount(0, client.Created);
        db.VulnerabilityMatches.Add(new VulnerabilityMatch
        {
            VulnerabilityId = 0, PackageArtifact = artifact, PackageArtifactId = artifact.Id, Active = true,
            Vulnerability = new Vulnerability { SourceId = "GHSA-test", Aliases = "[\"CVE-2099-1234\"]", Ecosystem = "nuget", PackageName = artifact.Name }
        });
        await db.SaveChangesAsync();
        await monitoring.SynchronizeAsync();
        Assert.HasCount(1, client.Created);
        Assert.Contains("CVE-2099-1234", client.Created[0].Content!);
        Assert.AreEqual(report.Id, (await db.BuildChecks.SingleAsync()).Id);
    }

    [TestMethod]
    public async Task NewCompliantBaselineMitigatesOnlyS360AndDoesNotWaitForPipelineSuccess()
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        FreshAudit(db);
        db.BuildChecks.Add(Report(_repository, false));
        await db.SaveChangesAsync();
        var client = new FakeClient();
        var state = new BaselineMonitorState();
        var monitoring = await Monitor(scope, client, state);
        await monitoring.SynchronizeAsync();
        var pipelineIncident = client.Add(_repository, "GitLab.Pipeline");
        db.BuildChecks.Add(Report(_repository, true));
        await db.SaveChangesAsync();
        await monitoring.SynchronizeAsync();
        Assert.HasCount(1, client.Mitigated);
        Assert.AreEqual("new", pipelineIncident.Status);
        Assert.IsTrue(state.LastRun!.Succeeded);
    }

    [TestMethod]
    [DataRow("review")]
    [DataRow("incomplete")]
    [DataRow("stale")]
    [DataRow("failed")]
    [DataRow("missing")]
    [DataRow("merge-request")]
    public async Task InadequateRecoveryEvidenceNeverMitigates(string condition)
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        FreshAudit(db, stale: condition == "stale", failed: condition == "failed");
        if (condition is not "missing") db.BuildChecks.Add(Report(_repository, true,
            purpose: condition == "review" ? "review" : "baseline", batches: condition == "incomplete" ? 2 : 1,
            pipelineSource: condition == "merge-request" ? "merge_request_event" : "push"));
        await db.SaveChangesAsync();
        var client = new FakeClient();
        client.Add(_repository);
        await (await Monitor(scope, client, new BaselineMonitorState())).SynchronizeAsync();
        Assert.HasCount(0, client.Mitigated);
        Assert.HasCount(0, client.Created);
    }

    [TestMethod]
    public async Task AggregatesSolutionsAndAnotherSolutionCannotClearTheRemainingFinding()
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        FreshAudit(db);
        db.BuildChecks.AddRange(Report(_repository + "//First.sln", true), Report(_repository + "//Second.sln", false));
        await db.SaveChangesAsync();
        var client = new FakeClient();
        var monitoring = await Monitor(scope, client, new BaselineMonitorState());
        await monitoring.SynchronizeAsync();
        Assert.HasCount(1, client.Created);
        await monitoring.SynchronizeAsync();
        Assert.HasCount(0, client.Mitigated);
    }

    [TestMethod]
    public async Task ManualResolutionOrRecoveryFollowedByRecurrenceCreatesANewIncident()
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        db.BuildChecks.Add(Report(_repository, false));
        await db.SaveChangesAsync();
        var client = new FakeClient();
        var monitoring = await Monitor(scope, client, new BaselineMonitorState());
        await monitoring.SynchronizeAsync();
        client.Items[0].Status = "resolved";
        await monitoring.SynchronizeAsync();
        Assert.HasCount(2, client.Created);
        client.Items[1].Status = "mitigated";
        await monitoring.SynchronizeAsync();
        Assert.HasCount(3, client.Created);
        Assert.AreEqual(3, client.Created.Select(c => c.ReportId).Distinct().Count());
    }

    [TestMethod]
    public async Task DisabledIntegrationAndInvalidConfigurationMakeNoRemoteCalls()
    {
        using var scope = Server!.Services.CreateScope();
        var client = new FakeClient();
        await (await Monitor(scope, client, new BaselineMonitorState(), enabled: false)).SynchronizeAsync();
        var monitoring = await Monitor(scope, client, new BaselineMonitorState());
        await scope.ServiceProvider.GetRequiredService<GlobalSettingsService>().UpdateSettingAsync(SettingsMap.AlertCenterApiKey, "");
        await monitoring.SynchronizeAsync();
        Assert.AreEqual(0, client.Queries);
    }

    [TestMethod]
    public async Task DisablingRecoveryPreservesTheIncident()
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        FreshAudit(db); db.BuildChecks.Add(Report(_repository, true)); await db.SaveChangesAsync();
        var client = new FakeClient();client.Add(_repository);
        await (await Monitor(scope, client, new BaselineMonitorState(), autoMitigate: false)).SynchronizeAsync();
        Assert.HasCount(0, client.Mitigated);
    }

    [TestMethod]
    public async Task InconsistentPaginationOrRemoteFailureStopsRecovery()
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        FreshAudit(db);db.BuildChecks.Add(Report(_repository, true));await db.SaveChangesAsync();
        var client = new FakeClient { BadPage = true };client.Add(_repository);
        var state = new BaselineMonitorState();
        await (await Monitor(scope, client, state)).SynchronizeAsync();
        Assert.HasCount(0, client.Mitigated);Assert.IsFalse(state.LastRun!.Succeeded);
        client.BadPage = false;client.ThrowOnQuery = true;
        await (await Monitor(scope, client, state)).SynchronizeAsync();
        Assert.HasCount(0, client.Mitigated);Assert.IsFalse(state.LastRun!.Succeeded);
    }

    [TestMethod]
    public async Task ChangedFindingsPatchSameIncidentAndUpdateFailureDoesNotDuplicateIt()
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        db.BuildChecks.Add(Report(_repository, false));await db.SaveChangesAsync();
        var client = new FakeClient(); var state = new BaselineMonitorState();
        var monitoring = await Monitor(scope, client, state);
        await monitoring.SynchronizeAsync();
        db.BuildChecks.Add(Report(_repository, false));await db.SaveChangesAsync();
        client.ThrowOnPatch = true;await monitoring.SynchronizeAsync();
        Assert.IsFalse(state.LastRun!.Succeeded);Assert.HasCount(1, client.Created);
        client.ThrowOnPatch = false;await monitoring.SynchronizeAsync();
        Assert.IsTrue(state.LastRun!.Succeeded);Assert.AreEqual(1, client.Patches);Assert.HasCount(1, client.Created);
    }

    [TestMethod]
    public async Task MoreThanOnePageOfProjectsIsAssessedAndPersonalOrRetiredProjectsAreExcluded()
    {
        using var scope = Server!.Services.CreateScope();
        var db = _db;
        for (var i = 0; i < 22; i++) db.BuildChecks.Add(Report(_repository + "-" + i, false));
        db.BuildChecks.AddRange(Report("anduin/private", false), Report("aiursoft/hom", false));
        await db.SaveChangesAsync();
        var client = new FakeClient();
        await (await Monitor(scope, client, new BaselineMonitorState())).SynchronizeAsync();
        Assert.HasCount(22, client.Created);
        Assert.IsFalse(client.Created.Any(c => c.Title.Contains("anduin/private") || c.Title.Contains("aiursoft/hom")));
    }

    [TestMethod]
    public async Task MonitoringPageRequiresItsOwnPermissionAndRetainsCsrfProtection()
    {
        Assert.AreEqual(HttpStatusCode.Redirect, (await Http.GetAsync("/AlertMonitoring")).StatusCode);
        await LoginAsAdmin();
        var response = await Http.GetAsync("/AlertMonitoring");
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Two incidents, independent recovery", await response.Content.ReadAsStringAsync());
        Assert.AreEqual(HttpStatusCode.BadRequest, (await Http.PostAsync("/AlertMonitoring/SaveRecovery", new FormUrlEncodedContent(new Dictionary<string,string>()))).StatusCode);
    }

    [TestMethod]
    public async Task OrdinaryUserCannotManageIntegration()
    {
        await RegisterAndLoginAsync();
        var response = await Http.GetAsync("/AlertMonitoring");
        Assert.AreEqual(HttpStatusCode.Redirect, response.StatusCode);
        Assert.Contains("/Error/Code403", response.Headers.Location!.ToString());
    }

    [TestMethod]
    public async Task PublishedSdkAdapterAuthenticatesAndUsesTheIncidentProtocolOverHttp()
    {
        using var scope = Server!.Services.CreateScope();
        var settings = scope.ServiceProvider.GetRequiredService<GlobalSettingsService>();
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var endpoint = builder.Build();
        var requests = 0;
        endpoint.MapGet("/api/v1/incidents", (HttpRequest request) =>
        {
            Assert.AreEqual("Bearer isolated-sdk-key", request.Headers.Authorization.ToString());
            Assert.AreEqual(BaselineMonitoringService.Source, request.Query["MetadataValue"].ToString());
            requests++;
            return Results.Json(new QueryIncidentsResponse { Code = Code.ResultShown, Message = "Result shown.", ProtocolVersion = typeof(AiurProtocolClient).Assembly.GetName().Version, Page = 1, PageSize = 100 });
        });
        endpoint.MapPost("/api/v1/incidents", async (HttpRequest request) =>
        {
            Assert.AreEqual("Bearer isolated-sdk-key", request.Headers.Authorization.ToString());
            Assert.Contains("SDK protocol test", await new StreamReader(request.Body).ReadToEndAsync());
            requests++;
            return Results.Json(new CreateIncidentResponse { Code = Code.ResultShown, Message = "Result shown.", ProtocolVersion = typeof(AiurProtocolClient).Assembly.GetName().Version, IncidentId = Guid.NewGuid() });
        });
        await endpoint.StartAsync();
        await settings.UpdateSettingAsync(SettingsMap.AlertCenterEndpoint, endpoint.Urls.Single());
        await settings.UpdateSettingAsync(SettingsMap.AlertCenterApiKey, "isolated-sdk-key");
        var client = ActivatorUtilities.CreateInstance<BaselineIncidentClient>(scope.ServiceProvider, new AlertCenterSettingsProvider(settings));
        var result = await client.QueryAsync(new QueryIncidentsRequest { Page = 1, PageSize = 100,
            MetadataKey = "source", MetadataValue = BaselineMonitoringService.Source, ActiveOnly = true });
        Assert.AreEqual(0, result.TotalCount);
        var created = await client.CreateAsync(new CreateIncidentRequest { ReportId = Guid.NewGuid(), Title = "SDK protocol test",
            Level = "sev2", OccurredAtUtc = DateTimeOffset.UtcNow });
        Assert.AreNotEqual(Guid.Empty, created.IncidentId);
        Assert.AreEqual(2, requests);
        await endpoint.StopAsync();
    }

    private sealed class FakeClient : IBaselineIncidentClient
    {
        public List<IncidentDetails> Items { get; } = [];
        public List<CreateIncidentRequest> Created { get; } = [];
        public List<Guid> Mitigated { get; } = [];
        public int Queries { get; private set; }
        public int Patches { get; private set; }
        public bool BadPage { get; set; }
        public bool ThrowOnQuery { get; set; }
        public bool ThrowOnPatch { get; set; }
        public IncidentDetails Add(string repository, string source = BaselineMonitoringService.Source)
        {
            var item = new IncidentDetails { IncidentId = Guid.NewGuid(), Version = Guid.NewGuid(), Status = "new",
                Metadata = new JObject { ["source"] = source, ["repository"] = repository } };
            Items.Add(item);return item;
        }
        public Task<QueryIncidentsResponse> QueryAsync(QueryIncidentsRequest request)
        {
            Queries++;
            if (ThrowOnQuery) throw new HttpRequestException("Isolated failure");
            var active = Items.Where(i => i.Status == "new").ToList();
            return Task.FromResult(new QueryIncidentsResponse { Items = active.Skip((request.Page - 1) * 100).Take(100).ToList(),
                TotalCount = active.Count, PageSize = 100, Page = BadPage ? 0 : request.Page });
        }
        public Task<CreateIncidentResponse> CreateAsync(CreateIncidentRequest request)
        {
            Created.Add(request);var item = Add(request.Metadata!.Value<string>("repository")!);item.Metadata = (JObject)request.Metadata.DeepClone();
            return Task.FromResult(new CreateIncidentResponse { IncidentId = item.IncidentId });
        }
        public Task<MitigateIncidentResponse> MitigateAsync(Guid id, MitigateIncidentRequest request)
        {
            Mitigated.Add(id);Items.Single(i => i.IncidentId == id).Status = "mitigated";
            return Task.FromResult(new MitigateIncidentResponse());
        }
        public Task<PatchIncidentMetadataResponse> PatchAsync(Guid id, PatchIncidentMetadataRequest request)
        {
            if (ThrowOnPatch) throw new InvalidOperationException("Version conflict");
            Patches++;Items.Single(i => i.IncidentId == id).Metadata[request.Property] = request.Value;
            return Task.FromResult(new PatchIncidentMetadataResponse());
        }
    }
}
