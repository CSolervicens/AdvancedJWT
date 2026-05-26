using Microsoft.EntityFrameworkCore;
using AdvancedJWT.Data;

namespace AdvancedJWT.Services;

public class SqliteAuthDataService : IAuthDataService
{
    private readonly AppDbContext _context;

    public SqliteAuthDataService(AppDbContext context)
    {
        _context = context;
    }

    public async Task<User?> GetUserByEmailAsync(string email)
    {
        return await _context.Users
            .FirstOrDefaultAsync(x => x.Email == email);
    }

    public async Task AddRefreshTokenAsync(RefreshToken token)
    {
        _context.RefreshTokens.Add(token);
        await _context.SaveChangesAsync();
    }

    public async Task AddRevokedTokenAsync(RevokedToken token)
    {
        _context.RevokedTokens.Add(token);
        await _context.SaveChangesAsync();
    }

    public async Task<UserSession?> GetUserSessionByRefreshTokenHashAsync(string hash)
    {
        return await _context.UserSessions
            .Include(x => x.User)
            .FirstOrDefaultAsync(x => x.RefreshTokenHash == hash);
    }

    public async Task AddUserSessionAsync(UserSession session)
    {
        _context.UserSessions.Add(session);
        await _context.SaveChangesAsync();
    }

    public async Task UpdateUserSessionAsync(UserSession session)
    {
        _context.UserSessions.Update(session);
        await _context.SaveChangesAsync();
    }

    public async Task RevokeAllUserSessionsAsync(Guid userId)
    {
        var sessions = await _context.UserSessions
            .Where(x => x.UserId == userId && x.RevokedAt == null)
            .ToListAsync();

        foreach (var session in sessions)
        {
            session.RevokedAt = DateTime.UtcNow;
        }

        await _context.SaveChangesAsync();
    }

    public async Task<bool> IsTokenRevokedAsync(string jwtId)
    {
        return await _context.RevokedTokens
            .AnyAsync(x => x.JwtId == jwtId && x.ExpiresAt > DateTime.UtcNow);
    }

    public async Task SaveChangesAsync()
    {
        await _context.SaveChangesAsync();
    }
}
