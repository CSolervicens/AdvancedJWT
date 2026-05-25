using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<RsaKeyService>();
builder.Services.AddScoped<IAuthDataService, MockAuthDataService>();
builder.Services.AddScoped<PasswordService>();
builder.Services.AddScoped<JwtService>();
builder.Services.AddScoped<DeviceFingerprintService>();
builder.Services.AddScoped<CsrfService>();

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "AdvancedJWT API",
        Version = "v1",
        Description = "Advanced JWT Authentication API with security features"
    });

    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token in the text input below.",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var rsaService = new RsaKeyService();

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
    options.TokenValidationParameters =
        new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ClockSkew = TimeSpan.Zero,

            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],

            IssuerSigningKey =
                new RsaSecurityKey(
                    rsaService.GetPublicKey()
                )
        };

    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = async context =>
        {
            var dataService = context.HttpContext.RequestServices
                .GetRequiredService<IAuthDataService>();

            var jti = context.Principal?
                .FindFirst(JwtRegisteredClaimNames.Jti)?
                .Value;

            if (jti == null)
            {
                context.Fail("Missing JTI");
                return;
            }

            var revoked = await dataService.IsTokenRevokedAsync(jti);

            if (revoked)
            {
                context.Fail("Token revoked");
            }
        }
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    Console.WriteLine("Development: Swagger Habilitado");
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "AdvancedJWT API v1");
        options.RoutePrefix = string.Empty; // Set Swagger UI at the app's root
    });
}
else
    Console.WriteLine("Produccion: Swagger no Habilitado");

app.UseHttpsRedirection();

// Secure Headers Middleware

app.UseHsts();

app.UseHsts();

app.Use(async (ctx, next) =>
{
    ctx.Response.Headers.Append(
        "X-Frame-Options",
        "DENY");

    ctx.Response.Headers.Append(
        "X-Content-Type-Options",
        "nosniff");

    ctx.Response.Headers.Append(
        "Referrer-Policy",
        "no-referrer");

    ctx.Response.Headers.Append(
        "Content-Security-Policy",
        "default-src 'self'");

    await next();
});

// -----------------------------

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();


//Los endpoints a proteger deben quedar con la anotacion [Authorize]

/* Usar sólo los cleims mínimos!!!
   Los demas datos se puden obtener de la BD antes de validar el acceso a un endpoint específico
Deberia validarse el Rol del claim dado el Usuario.
 
{
  "sub": "user-id",
  "email": "user@email.com",
  "role": "Admin",
  "jti": "guid"
} 


En JavaScript:

const entropy = crypto.randomUUID();
localStorage.setItem("device_entropy", entropy);

LOGIN ENDPOINT:

[HttpPost("login")]
public async Task<IActionResult> Login(LoginRequest request)
{
    var user = await _db.Users
        .FirstOrDefaultAsync(x => x.Email == request.Email);

    if (user == null)
        return Unauthorized();

    if (!_passwordService.VerifyPassword(
        request.Password,
        user.PasswordHash))
    {
        return Unauthorized();
    }

    var fingerprint =
        _fingerprintService.Generate(
            Request,
            Request.Headers["X-Device-Entropy"]
        );

    var refreshToken =
        TokenGenerator.GenerateSecureToken();

    var refreshHash =
        TokenGenerator.Sha256(refreshToken);

    var (accessToken, jti) =
        _jwtService.GenerateAccessToken(user);

    var session = new UserSession
    {
        UserId = user.Id,
        DeviceFingerprint = fingerprint,
        RefreshTokenHash = refreshHash,
        JwtId = jti,
        CreatedAt = DateTime.UtcNow,
        ExpiresAt = DateTime.UtcNow.AddDays(7),
        IpAddress = HttpContext.Connection
            .RemoteIpAddress?.ToString() ?? "",
        UserAgent = Request.Headers.UserAgent!
    };

    _db.UserSessions.Add(session);

    await _db.SaveChangesAsync();

    SetRefreshCookie(refreshToken);

    return Ok(new
    {
        accessToken,
        csrfToken = _csrfService.Generate()
    });
}



CSFR Token
===========
{
  "accessToken": "...",
  "csrfToken": "random-value"
}
Frontend stores token in memory.

Frontend Request:
X-CSRF-TOKEN: random-value


CsfrMiddleware.cs
=================
public class CsrfMiddleware
{
    private readonly RequestDelegate _next;

    public CsrfMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        if (
            HttpMethods.IsPost(context.Request.Method) ||
            HttpMethods.IsPut(context.Request.Method) ||
            HttpMethods.IsDelete(context.Request.Method)
        )
        {
            var csrfCookie =
                context.Request.Cookies["XSRF-TOKEN"];

            var csrfHeader =
                context.Request.Headers["X-CSRF-TOKEN"];

            if (
                string.IsNullOrEmpty(csrfCookie) ||
                string.IsNullOrEmpty(csrfHeader) ||
                csrfCookie != csrfHeader
            )
            {
                context.Response.StatusCode = 403;
                return;
            }
        }

        await _next(context);
    }
}


CSFR Cookie
===========

Response.Cookies.Append(
    "XSRF-TOKEN",
    csrfToken,
    new CookieOptions
    {
        HttpOnly = false,
        Secure = true,
        SameSite = SameSiteMode.Strict
    });


Refresh Cookie
==============

private void SetRefreshCookie(string token)
{
    Response.Cookies.Append(
        "refreshToken",
        token,
        new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Expires = DateTimeOffset.UtcNow.AddDays(7)
        });
}

*/
