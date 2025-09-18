using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;

namespace ProjectCodwer.Data
{
    public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext<ApplicationUser>(options), IDataProtectionKeyContext
    {
        public DbSet<SecurityAuditLog> SecurityAuditLogs { get; set; }
        public DbSet<DataProtectionKey> DataProtectionKeys { get; set; }
    }
}
