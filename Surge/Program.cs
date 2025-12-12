using Surge.Components;
using Surge.Options;
using Surge.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddOptions<RuleProcessingOptions>()
    .BindConfiguration("RuleProcessing")
    .ValidateDataAnnotations()
    .ValidateOnStart();

builder.Services.AddSingleton<RuleProcessingService>();
builder.Services.AddSingleton<RuleSetIndexService>();
builder.Services.AddSingleton<RuleSetFileService>();
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

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
