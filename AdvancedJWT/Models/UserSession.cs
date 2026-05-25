public class UserSession
{
    public Guid Id { get; set; }
    public Guid UserId { get; set; }
    public User? User { get; set; }
    public string DeviceFingerprint { get; set; } = default!;
    public string RefreshTokenHash { get; set; } = default!;
    public string JwtId { get; set; } = default!;
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public string? ReplacedByTokenHash { get; set; }
    public string IpAddress { get; set; } = default!;
    public string UserAgent { get; set; } = default!;
}
