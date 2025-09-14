using ProjectCodwer.Data;

namespace ProjectCodwer.Services
{
    public class SecurityAuditService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<SecurityAuditService> _logger;

        public SecurityAuditService(ApplicationDbContext context, ILogger<SecurityAuditService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task LogSecurityEventAsync(string userId, string eventType, string ipAddress, string? details = null)
        {
            var auditLog = new SecurityAuditLog
            {
                UserId = userId,
                EventType = eventType,
                Timestamp = DateTime.UtcNow,
                IpAddress = ipAddress,
                Details = details
            };

            _context.SecurityAuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();
            
            _logger.LogInformation("Security event: {EventType} for user {UserId} from {IpAddress}", 
                eventType, userId, ipAddress);
        }
    }
}