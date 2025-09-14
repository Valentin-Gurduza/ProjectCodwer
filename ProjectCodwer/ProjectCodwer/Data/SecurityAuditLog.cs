namespace ProjectCodwer.Data
{
    public class SecurityAuditLog
    {
        public int Id { get; set; }
        public string UserId { get; set; } = string.Empty;
        public string EventType { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string IpAddress { get; set; } = string.Empty;
        public string? Details { get; set; }
    }
}