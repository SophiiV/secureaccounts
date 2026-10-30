using Microsoft.EntityFrameworkCore;

namespace SecureAccounts.Data;

public class AppDbContext(DbContextOptions<AppDbContext> options) : DbContext(options)
{
    public DbSet<AppUser> Users => Set<AppUser>();
    public DbSet<AccountToken> Tokens => Set<AccountToken>();
    public DbSet<LoginAttempt> LoginAttempts => Set<LoginAttempt>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<AppUser>(e =>
        {
            e.HasIndex(u => u.Email).IsUnique();
            e.HasIndex(u => u.GoogleSubject).IsUnique();
            e.Property(u => u.Email).HasMaxLength(256);
            e.Property(u => u.DisplayName).HasMaxLength(100);
            e.Property(u => u.Role).HasMaxLength(20);
        });
        b.Entity<AccountToken>(e =>
        {
            e.HasIndex(t => t.TokenHash).IsUnique();
            e.HasOne(t => t.User).WithMany().HasForeignKey(t => t.UserId).OnDelete(DeleteBehavior.Cascade);
        });
        b.Entity<LoginAttempt>(e =>
        {
            e.HasIndex(a => a.Time);
            e.HasIndex(a => a.Login);
            e.Property(a => a.Result).HasConversion<string>().HasMaxLength(30);
        });
    }
}
