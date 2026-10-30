using System.Text.Encodings.Web;
using System.Text.Unicode;
using System.Threading.RateLimiting;
using Microsoft.Extensions.WebEncoders;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SecureAccounts.Data;
using SecureAccounts.Services;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;

string dataDir = Path.Combine(builder.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(dataDir);

builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseSqlite($"Data Source={Path.Combine(dataDir, "accounts.db")}"));

// Ключі Data Protection (cookie, секрети TOTP) зберігаються на диску, у Windows зашифровані DPAPI
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("SecureAccounts")
    .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(dataDir, "keys")));
if (OperatingSystem.IsWindows())
    dataProtection.ProtectKeysWithDpapi();

builder.Services.Configure<SecurityOptions>(config.GetSection("Security"));
builder.Services.Configure<SmtpOptions>(config.GetSection("Smtp"));
builder.Services.Configure<AppOptions>(config.GetSection("App"));

builder.Services.AddSingleton<PasswordHasher>();
builder.Services.AddSingleton<PasswordPolicy>();
builder.Services.AddSingleton<CaptchaService>();
builder.Services.AddSingleton<TotpService>();
builder.Services.AddScoped<EmailSender>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddScoped<AccountService>();

// Кирилиця виводиться як є; спецсимволи HTML (<, >, &, ") енкодер і далі екранує
builder.Services.Configure<WebEncoderOptions>(o => o.TextEncoderSettings = new TextEncoderSettings(UnicodeRanges.All));

builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(o =>
{
    o.Cookie.Name = "sa.session";
    o.Cookie.HttpOnly = true;
    o.Cookie.SameSite = SameSiteMode.Lax;
    o.Cookie.IsEssential = true;
    o.IdleTimeout = TimeSpan.FromMinutes(20);
});

// ---------- автентифікація ----------
string? googleId = config["Authentication:Google:ClientId"]?.Trim();
string? googleSecret = config["Authentication:Google:ClientSecret"]?.Trim();
bool googleEnabled = !string.IsNullOrWhiteSpace(googleId) && !string.IsNullOrWhiteSpace(googleSecret);
builder.Services.AddSingleton(new ExternalLoginOptions(googleEnabled));

var auth = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, o =>
    {
        o.Cookie.Name = "sa.auth";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.LoginPath = "/Account/Login";
        o.LogoutPath = "/Account/Logout";
        o.AccessDeniedPath = "/Account/AccessDenied";
        o.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        o.SlidingExpiration = true;
        o.Events.OnValidatePrincipal = AccountService.ValidatePrincipalAsync;
    })
    .AddCookie(AuthSchemes.TwoFactor, o =>          // пароль перевірено, чекаємо код 2FA
    {
        o.Cookie.Name = "sa.2fa";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
        o.SlidingExpiration = false;
    })
    .AddCookie(AuthSchemes.External, o =>           // результат входу через Google до прив'язки до запису
    {
        o.Cookie.Name = "sa.ext";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Lax;
        o.ExpireTimeSpan = TimeSpan.FromMinutes(5);
    });

if (googleEnabled)
{
    // OpenID Connect: Authorization Code Flow + PKCE, ID-токен перевіряється за ключами Google (JWKS)
    auth.AddOpenIdConnect(AuthSchemes.Google, "Google", o =>
    {
        o.SignInScheme = AuthSchemes.External;
        o.Authority = "https://accounts.google.com";
        o.ClientId = googleId;
        o.ClientSecret = googleSecret;
        o.ResponseType = "code";
        o.ResponseMode = "query";
        o.UsePkce = true;
        o.CallbackPath = "/signin-google";
        o.Scope.Clear();
        o.Scope.Add("openid");
        o.Scope.Add("email");
        o.Scope.Add("profile");
        o.Prompt = "select_account";
        o.MapInboundClaims = false;
        o.GetClaimsFromUserInfoEndpoint = true;
        o.SaveTokens = false;
        o.CorrelationCookie.SameSite = SameSiteMode.Lax;
        o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.NonceCookie.SameSite = SameSiteMode.Lax;
        o.NonceCookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        o.Events.OnRemoteFailure = ctx =>
        {
            ctx.Response.Redirect("/Account/Login?external=failed");
            ctx.HandleResponse();
            return Task.CompletedTask;
        };
    });
}

// ---------- розмежування доступу (RBAC) ----------
builder.Services.AddAuthorization(o => o.AddPolicy("AdminOnly", p => p.RequireRole(Roles.Admin)));

builder.Services.AddRazorPages(o =>
{
    o.Conventions.AuthorizeFolder("/Profile");
    o.Conventions.AuthorizeFolder("/Admin", "AdminOnly");
});

// ---------- обмеження частоти запитів з однієї IP (додатковий захист від підбору) ----------
int postsPerMinute = config.GetValue("Security:RateLimitPostsPerMinute", 20);
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    // рахуються лише надсилання форм (POST) на сторінках входу, реєстрації, 2FA і відновлення пароля
    o.AddPolicy("auth", ctx => HttpMethods.IsPost(ctx.Request.Method)
        ? RateLimitPartition.GetFixedWindowLimiter(ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = postsPerMinute, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 })
        : RateLimitPartition.GetNoLimiter("read"));
    o.OnRejected = async (ctx, token) =>
    {
        ctx.HttpContext.Response.ContentType = "text/plain; charset=utf-8";
        await ctx.HttpContext.Response.WriteAsync("Забагато запитів з вашої IP-адреси. Спробуйте через хвилину.", token);
    };
});

builder.WebHost.UseUrls(config["App:BaseUrl"] ?? "http://localhost:5080");

var app = builder.Build();

using (var scope = app.Services.CreateScope())
    await SeedData.EnsureAdminAsync(scope.ServiceProvider, config, app.Logger);

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.Use(async (ctx, next) =>
{
    var h = ctx.Response.Headers;
    h["X-Content-Type-Options"] = "nosniff";
    h["X-Frame-Options"] = "DENY";
    h["Referrer-Policy"] = "strict-origin-when-cross-origin";
    h["Content-Security-Policy"] =
        "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; " +
        "form-action 'self' https://accounts.google.com; frame-ancestors 'none'; base-uri 'self'; object-src 'none'";
    await next();
});

app.UseRouting();
app.UseRateLimiter();
app.UseSession();
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();
app.MapRazorPages().WithStaticAssets();

// Зображення CAPTCHA: кожен запит генерує новий код і замінює попередній у сесії
app.MapGet("/captcha", (HttpContext http, CaptchaService captcha) =>
{
    http.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
    return Results.File(captcha.CreateImage(http.Session), "image/png");
});

app.Run();
