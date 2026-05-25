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

    public AuthController(
        IAuthDataService dataService,
        PasswordService passwordService,
        JwtService jwtService,
        DeviceFingerprintService fingerprintService,
        CsrfService csrfService)
    {
        _dataService = dataService;
        _passwordService = passwordService;
        _jwtService = jwtService;
        _fingerprintService = fingerprintService;
        _csrfService = csrfService;
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

        Console.WriteLine($"accessToken: {accessToken}");
        Console.WriteLine($"refreshToken: {refreshToken}");

        await _dataService.AddRefreshTokenAsync(new RefreshToken
        {
            UserId = user.Id,
            TokenHash = TokenGenerator.Sha256(refreshToken),
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CreatedAt = DateTime.UtcNow
        });

        await _dataService.SaveChangesAsync();

        SetRefreshCookie(refreshToken);

        return Ok(new
        {
            accessToken
        });
    }


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
        var refreshToken =
            Request.Cookies["refreshToken"];

        if (string.IsNullOrEmpty(refreshToken))
            return Unauthorized();

        var hash = TokenGenerator.Sha256(refreshToken);

        var session = await _dataService.GetUserSessionByRefreshTokenHashAsync(hash);

        if (session == null)
            return Unauthorized();

        if (session.RevokedAt != null)
        {
            // replay attack detected

            await _dataService.RevokeAllUserSessionsAsync(session.UserId);

            return Unauthorized();
        }

        if (session.ExpiresAt < DateTime.UtcNow)
            return Unauthorized();

        var fingerprint =
            _fingerprintService.Generate(
                Request,
                Request.Headers["X-Device-Entropy"]
            );

        if (fingerprint != session.DeviceFingerprint)
        {
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

        var newSession = new UserSession
        {
            UserId = session.UserId,
            DeviceFingerprint = session.DeviceFingerprint,
            RefreshTokenHash = newHash,
            JwtId = jti,
            CreatedAt = DateTime.UtcNow,
            ExpiresAt = DateTime.UtcNow.AddDays(7)
        };

        session.ReplacedByTokenHash = newHash;
        await _dataService.UpdateUserSessionAsync(session);

        await _dataService.AddUserSessionAsync(newSession);

        await _dataService.SaveChangesAsync();

        SetRefreshCookie(newRefresh);

        return Ok(new
        {
            accessToken = jwt,
            csrfToken = _csrfService.Generate()
        });
    }


}
