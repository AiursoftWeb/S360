using Aiursoft.CSTools.Tools;
using Aiursoft.Canon.TaskQueue;
using Aiursoft.Canon.BackgroundJobs;
using Aiursoft.Canon.ScheduledTasks;
using Aiursoft.DbTools.Switchable;
using Aiursoft.Scanner;
using Aiursoft.S360.Configuration;
using Aiursoft.WebTools.Abstractions.Models;
using Aiursoft.S360.InMemory;
using Aiursoft.S360.MySql;
using Aiursoft.S360.Services.Authentication;
using Aiursoft.S360.Services.BackgroundJobs;
using Aiursoft.S360.Sqlite;
using Aiursoft.UiStack;
using Aiursoft.UiStack.Layout;
using Aiursoft.UiStack.Navigation;
using Microsoft.AspNetCore.Mvc.Razor;
using Aiursoft.ClickhouseLoggerProvider;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Diagnostics.CodeAnalysis;
using Aiursoft.AiurProtocol.Server;
using Aiursoft.S360.Services.Vulnerability;
using Aiursoft.S360.Services.AlertMonitoring;
using Aiursoft.AiurProtocol;
using Aiursoft.S360.Services.Resolution;
using Microsoft.AspNetCore.Authentication;

namespace Aiursoft.S360;

[ExcludeFromCodeCoverage]
public class Startup : IWebStartup
{
    public void ConfigureServices(IConfiguration configuration, IWebHostEnvironment environment, IServiceCollection services)
    {
        // AppSettings.
        services.Configure<AppSettings>(configuration.GetSection("AppSettings"));

        // Relational database
        var (connectionString, dbType, allowCache) = configuration.GetDbSettings();
        services.AddSwitchableRelationalDatabase(
            dbType: EntryExtends.IsInUnitTests() ? "InMemory" : dbType,
            connectionString: connectionString,
            supportedDbs:
            [
                new MySqlSupportedDb(allowCache: allowCache, splitQuery: false),
                new SqliteSupportedDb(allowCache: allowCache, splitQuery: true),
                new InMemorySupportedDb()
            ]);

        services.AddLogging(builder =>
        {
            builder.AddClickhouse(options => configuration.GetSection("Logging:Clickhouse").Bind(options));
        });

        // Authentication and Authorization
        services.AddTemplateAuth(configuration);
        services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, S360CheckKeyHandler>(
            S360CheckKeyHandler.SchemeName, _ => { });

        // Services
        services.AddMemoryCache();
        services.AddSingleton<Services.ArtifactVerificationAdmission>();
        services.AddHttpClient();
        services.AddAiurProtocolClient();
        services.AddScoped<AlertCenterSettingsProvider>();
        services.AddScoped<IBaselineIncidentClient, BaselineIncidentClient>();
        services.AddScoped<BaselineMonitoringService>();
        services.AddSingleton<BaselineMonitorState>();
        services.AddHttpClient(PackageResolutionService.ArchiveClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
        services.AddSingleton<OsvRequestThrottle>();
        services.AddTransient<OsvRequestHandler>();
        services.AddHttpClient<OsvClient>(client => client.Timeout = TimeSpan.FromMinutes(2))
            .AddHttpMessageHandler<OsvRequestHandler>();
        services.AddScoped<PackageResolutionService>();
        services.AddScoped<IArtifactSourceVerifier, ArtifactSourceVerifier>();
        services.AddAssemblyDependencies(typeof(Startup).Assembly);
        services.AddSingleton<NavigationState<Startup>>();

        // Background job infrastructure
        services.AddTaskQueueEngine();
        services.AddScheduledTaskEngine();

        // Background jobs
        services.RegisterBackgroundJob<DummyJob>();
        var orphanAvatarCleanupJob = services.RegisterBackgroundJob<OrphanAvatarCleanupJob>();
        var baselineIncidentSyncJob = services.RegisterBackgroundJob<BaselineIncidentSyncJob>();
        var vulnerabilityAuditJob = services.RegisterBackgroundJob<VulnerabilityAuditJob>();
        var dependencyResolutionJob = services.RegisterBackgroundJob<DependencyResolutionJob>();

        // Scheduled tasks (attach a schedule to any registered background job)
        services.RegisterScheduledTask(
            registration: orphanAvatarCleanupJob,
            period:     TimeSpan.FromHours(6),
            startDelay: TimeSpan.FromMinutes(5));
        services.RegisterScheduledTask(
            registration: vulnerabilityAuditJob,
            period: TimeSpan.FromHours(6),
            startDelay: TimeSpan.FromMinutes(2));
        services.RegisterScheduledTask(
            registration: dependencyResolutionJob,
            period: TimeSpan.FromMinutes(1),
            startDelay: TimeSpan.FromMinutes(1));

        services.RegisterScheduledTask(
            registration: baselineIncidentSyncJob,
            period: TimeSpan.FromMinutes(1),
            startDelay: TimeSpan.FromMinutes(1));

        // Controllers and localization
        services.AddControllersWithViews()
            .AddAiurProtocol()
            .AddNewtonsoftJson(options =>
            {
                options.SerializerSettings.DateTimeZoneHandling = DateTimeZoneHandling.Utc;
                options.SerializerSettings.ContractResolver = new DefaultContractResolver();
            })
            .AddApplicationPart(typeof(Startup).Assembly)
            .AddApplicationPart(typeof(UiStackLayoutViewModel).Assembly)
            .AddViewLocalization(LanguageViewLocationExpanderFormat.Suffix)
            .AddDataAnnotationsLocalization();
    }

    public void Configure(WebApplication app)
    {
        app.UseExceptionHandler("/Error/Code500");
        app.UseStatusCodePagesWithReExecute("/Error/Code{0}");
        app.UseUIStack();
        app.UseStaticFiles();
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapGet("/health", () => Results.Ok("OK"));
        app.MapDefaultControllerRoute();
    }
}
