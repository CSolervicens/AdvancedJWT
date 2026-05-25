public class MockAuthDataService : IAuthDataService
{
    private readonly List<User> _users = new();
    private readonly List<RefreshToken> _refreshTokens = new();
    private readonly List<RevokedToken> _revokedTokens = new();
    private readonly List<UserSession> _userSessions = new();

    public MockAuthDataService()
    {
        // Seed with a test user
        _users.Add(new User
        {
            Id = Guid.NewGuid(),
            Email = "test@example.com",
            PasswordHash = "NFgxZA5Rr2mqtU6PwUrHKA==.yLOJBpoFQZcpkCVej2r2YFeN+QAVZoible/V3Z6PTlI=", // You'll need to generate a proper hash
            Role = "User"
        });
    }

    public Task<User?> GetUserByEmailAsync(string email)
    {
        var user = _users.FirstOrDefault(x => x.Email == email);
        return Task.FromResult(user);
    }

    public Task AddRefreshTokenAsync(RefreshToken token)
    {
        _refreshTokens.Add(token);
        return Task.CompletedTask;
    }

    public Task AddRevokedTokenAsync(RevokedToken token)
    {
        _revokedTokens.Add(token);
        return Task.CompletedTask;
    }

    public Task<UserSession?> GetUserSessionByRefreshTokenHashAsync(string hash)
    {
        var session = _userSessions.FirstOrDefault(x => x.RefreshTokenHash == hash);

        // Load the User navigation property
        if (session != null)
        {
            session.User = _users.FirstOrDefault(u => u.Id == session.UserId);
        }

        return Task.FromResult(session);
    }

    public Task AddUserSessionAsync(UserSession session)
    {
        _userSessions.Add(session);
        return Task.CompletedTask;
    }

    public Task UpdateUserSessionAsync(UserSession session)
    {
        // In-memory update - the reference is already being modified
        return Task.CompletedTask;
    }

    public Task RevokeAllUserSessionsAsync(Guid userId)
    {
        var sessions = _userSessions.Where(x => x.UserId == userId);
        foreach (var session in sessions)
        {
            session.RevokedAt = DateTime.UtcNow;
        }
        return Task.CompletedTask;
    }

    public Task<bool> IsTokenRevokedAsync(string jwtId)
    {
        var isRevoked = _revokedTokens.Any(x => 
            x.JwtId == jwtId && 
            x.ExpiresAt > DateTime.UtcNow);
        return Task.FromResult(isRevoked);
    }

    public Task SaveChangesAsync()
    {
        // No-op for in-memory mock
        return Task.CompletedTask;
    }
}
