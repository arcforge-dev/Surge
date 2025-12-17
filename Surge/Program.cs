using Surge.Components;
using Surge.Options;
using Surge.Services;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.StaticFiles;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

var runningInContainer = string.Equals(
    Environment.GetEnvironmentVariable("DOTNET_RUNNING_IN_CONTAINER"),
    "true",
    StringComparison.OrdinalIgnoreCase);

var keysDirectory = builder.Configuration["DataProtection:KeysDirectory"];
if (string.IsNullOrWhiteSpace(keysDirectory) && runningInContainer)
{
    keysDirectory = "/RuleSet/.aspnet/DataProtection-Keys";
}

if (!string.IsNullOrWhiteSpace(keysDirectory))
{
    builder.Services
        .AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(keysDirectory))
        .SetApplicationName("Surge");
}

builder.Services.AddOptions<RuleProcessingOptions>()
    .BindConfiguration("RuleProcessing")
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddSingleton<RuleProcessingService>();
builder.Services.AddSingleton<RuleSetIndexService>();
builder.Services.AddSingleton<RuleSetFileService>();
builder.Services.AddSingleton<RuleRepositorySyncService>();
builder.Services.AddHostedService<RuleProcessingHostedService>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

var contentTypeProvider = new FileExtensionContentTypeProvider();
contentTypeProvider.Mappings[".conf"] = "text/plain";
app.UseStaticFiles(new StaticFileOptions
{
    ContentTypeProvider = contentTypeProvider
});

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
