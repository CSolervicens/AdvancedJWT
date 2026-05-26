using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;


[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly IAuthDataService _dataService;
    private readonly PasswordService _passwordService;
    private readonly JwtService _jwtService;
    private readonly DeviceFingerprintService _fingerprintService;
    private readonly CsrfService _csrfService;
    private readonly IConfiguration _config;

    public AuthController(
        IAuthDataService dataService,
        PasswordService passwordService,
        JwtService jwtService,
        DeviceFingerprintService fingerprintService,
        CsrfService csrfService,
        IConfiguration config)
    {
        _dataService = dataService;
        _passwordService = passwordService;
        _jwtService = jwtService;
        _fingerprintService = fingerprintService;
        _csrfService = csrfService;
        _config = config;
}

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        var user = await _dataService.GetUserByEmailAsync(request.Email);

        if (user == null)
            return Unauthorized();

        if (!_passwordService.VerifyPassword(
            request.Password,
            user.PasswordHash))
        {
            return Unauthorized();
        }

        var (accessToken, jti) = _jwtService.GenerateAccessToken(user);

        var refreshToken = TokenGenerator.GenerateSecureToken();
        var refreshTokenHash = TokenGenerator.Sha256(refreshToken);

        double RefreshToken_Minutes = double.Parse(_config["Jwt:RefreshToken_Minutes"]);
        Console.WriteLine($"RefreshToken_Minutes: {RefreshToken_Minutes}");

        var fingerprint = _fingerprintService.Generate(
            Request,
            Request.Headers["X-Device-Entropy"]
        );

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (string.IsNullOrEmpty(ipAddress))
        {
            ipAddress = "unknown";
        }

        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrEmpty(userAgent))
        {
            userAgent = "unknown";
        }

        var userSession = new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = user.Id,
            DeviceFingerprint = fingerprint,
            RefreshTokenHash = refreshTokenHash,
            JwtId = jti,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(RefreshToken_Minutes),
            IpAddress = ipAddress,
            UserAgent = userAgent
        };

        await _dataService.AddUserSessionAsync(userSession);
        await _dataService.SaveChangesAsync();

        SetRefreshCookie(refreshToken);

        return Ok(new
        {
            accessToken,
            csrfToken = _csrfService.Generate()
        });
    }


    private void SetRefreshCookie(string token)
    {
        double RefreshToken_Minutes = double.Parse(_config["Jwt:RefreshToken_Minutes"]);
        Console.WriteLine($"RefreshToken_Minutes: {RefreshToken_Minutes}");

        Response.Cookies.Append(
            "refreshToken",
            token,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(RefreshToken_Minutes)
            });
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        var jti = User.FindFirst(
            JwtRegisteredClaimNames.Jti)?.Value;

        var exp = User.FindFirst(
            JwtRegisteredClaimNames.Exp)?.Value;

        if (jti != null && exp != null)
        {
            var expiry =
                DateTimeOffset
                    .FromUnixTimeSeconds(long.Parse(exp))
                    .UtcDateTime;

            await _dataService.AddRevokedTokenAsync(new RevokedToken
            {
                JwtId = jti,
                RevokedAt = DateTime.UtcNow,
                ExpiresAt = expiry
            });
        }

        var refreshToken =
            Request.Cookies["refreshToken"];

        if (!string.IsNullOrEmpty(refreshToken))
        {
            var hash = TokenGenerator.Sha256(refreshToken);

            var session = await _dataService.GetUserSessionByRefreshTokenHashAsync(hash);

            if (session != null)
            {
                session.RevokedAt = DateTime.UtcNow;
                await _dataService.UpdateUserSessionAsync(session);
            }
        }

        await _dataService.SaveChangesAsync();

        Response.Cookies.Delete("refreshToken");

        return Ok();
    }


    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh()
    {
        
        Console.WriteLine("Refresh endpoint called");

        var refreshToken =
            Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(refreshToken))
            return Unauthorized();

        var hash = TokenGenerator.Sha256(refreshToken);

        var session = await _dataService.GetUserSessionByRefreshTokenHashAsync(hash);

        if (session == null)
        {
            Console.WriteLine("No session found for the provided refresh token hash");
            return Unauthorized();
        }

        if (session.RevokedAt != null)
        {
            // replay attack detected
            Console.WriteLine("Replay attack detected: refresh token has already been revoked");

            await _dataService.RevokeAllUserSessionsAsync(session.UserId);

            return Unauthorized();
        }

        if (session.ExpiresAt < DateTime.UtcNow)
        {
            Console.WriteLine("Refresh token has expired");
            return Unauthorized();
        }

        var fingerprint =
            _fingerprintService.Generate(
                Request,
                Request.Headers["X-Device-Entropy"]
            );

        if (fingerprint != session.DeviceFingerprint)
        {
            Console.WriteLine("Device fingerprint mismatch detected");
            await _dataService.RevokeAllUserSessionsAsync(session.UserId);

            return Unauthorized();
        }

        session.RevokedAt = DateTime.UtcNow;
        await _dataService.UpdateUserSessionAsync(session);

        var newRefresh =
            TokenGenerator.GenerateSecureToken();

        var newHash =
            TokenGenerator.Sha256(newRefresh);

        var (jwt, jti) =
            _jwtService.GenerateAccessToken(session.User);

        double RefreshToken_Minutes = double.Parse(_config["Jwt:RefreshToken_Minutes"]);
        Console.WriteLine($"RefreshToken_Minutes: {RefreshToken_Minutes}");

        var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString();
        if (string.IsNullOrEmpty(ipAddress))
        {
            ipAddress = "unknown";
        }

        var userAgent = Request.Headers.UserAgent.ToString();
        if (string.IsNullOrEmpty(userAgent))
        {
            userAgent = "unknown";
        }

        var newSession = new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = session.UserId,
            DeviceFingerprint = session.DeviceFingerprint,
            RefreshTokenHash = newHash,
            JwtId = jti,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddMinutes(RefreshToken_Minutes),
            IpAddress = ipAddress,
            UserAgent = userAgent
        };

        session.ReplacedByTokenHash = newHash;
        await _dataService.UpdateUserSessionAsync(session);

        await _dataService.AddUserSessionAsync(newSession);

        await _dataService.SaveChangesAsync();

        SetRefreshCookie(newRefresh);

        Console.WriteLine($"** New access token generated !!");

        return Ok(new
        {
            accessToken = jwt,
            csrfToken = _csrfService.Generate()
        });
    }


}
