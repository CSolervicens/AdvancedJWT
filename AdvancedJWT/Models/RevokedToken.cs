public class RevokedToken
{
    public Guid Id { get; set; }
    public string JwtId { get; set; } = default!;
    public DateTime RevokedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
}
