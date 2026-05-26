using Microsoft.EntityFrameworkCore;

namespace AdvancedJWT.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<User> Users { get; set; } = null!;
    public DbSet<RefreshToken> RefreshTokens { get; set; } = null!;
    public DbSet<RevokedToken> RevokedTokens { get; set; } = null!;
    public DbSet<UserSession> UserSessions { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // User entity configuration
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Email).IsUnique();
            entity.Property(e => e.Email).IsRequired().HasMaxLength(256);
            entity.Property(e => e.PasswordHash).IsRequired();
            entity.Property(e => e.Role).IsRequired().HasMaxLength(50);
        });

        // RefreshToken entity configuration
        modelBuilder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.TokenHash);
            entity.HasIndex(e => e.UserId);
            entity.Property(e => e.TokenHash).IsRequired();
        });

        // RevokedToken entity configuration
        modelBuilder.Entity<RevokedToken>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => new { e.JwtId, e.ExpiresAt });
            entity.Property(e => e.JwtId).IsRequired();
        });

        // UserSession entity configuration
        modelBuilder.Entity<UserSession>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.RefreshTokenHash);
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.JwtId);

            entity.Property(e => e.DeviceFingerprint).IsRequired();
            entity.Property(e => e.RefreshTokenHash).IsRequired();
            entity.Property(e => e.JwtId).IsRequired();
            entity.Property(e => e.IpAddress).IsRequired();
            entity.Property(e => e.UserAgent).IsRequired();

            // Configure relationship with User
            entity.HasOne(e => e.User)
                .WithMany()
                .HasForeignKey(e => e.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
