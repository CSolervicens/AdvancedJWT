public interface IAuthDataService
{
    Task<User?> GetUserByEmailAsync(string email);
    Task AddRefreshTokenAsync(RefreshToken token);
    Task AddRevokedTokenAsync(RevokedToken token);
    Task<UserSession?> GetUserSessionByRefreshTokenHashAsync(string hash);
    Task AddUserSessionAsync(UserSession session);
    Task UpdateUserSessionAsync(UserSession session);
    Task RevokeAllUserSessionsAsync(Guid userId);
    Task<bool> IsTokenRevokedAsync(string jwtId);
    Task SaveChangesAsync();
}
