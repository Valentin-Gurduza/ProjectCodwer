using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using ProjectCodwer.Data;
using System.Net;
using System.Net.Mail;

namespace ProjectCodwer.Services
{
    public class EmailService : IEmailSender<ApplicationUser>
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendConfirmationLinkAsync(ApplicationUser user, string email, string confirmationLink)
        {
            await SendEmailAsync(email, "Confirm your email", 
                $"Please confirm your account by <a href='{confirmationLink}'>clicking here</a>.");
        }

        public async Task SendPasswordResetLinkAsync(ApplicationUser user, string email, string resetLink)
        {
            await SendEmailAsync(email, "Reset your password", 
                $"Please reset your password by <a href='{resetLink}'>clicking here</a>.");
        }

        public async Task SendPasswordResetCodeAsync(ApplicationUser user, string email, string resetCode)
        {
            await SendEmailAsync(email, "Reset your password", 
                $"Please reset your password using the following code: {resetCode}");
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            try
            {
                var mailSettings = _configuration.GetSection("MailSettings");
                var fromEmail = mailSettings["FromEmail"];
                var smtpServer = mailSettings["SmtpServer"];
                var smtpPort = int.Parse(mailSettings["SmtpPort"] ?? "587");
                var smtpUsername = mailSettings["SmtpUsername"];
                var smtpPassword = mailSettings["SmtpPassword"];

                if (string.IsNullOrEmpty(fromEmail) || string.IsNullOrEmpty(smtpServer))
                {
                    _logger.LogWarning("Email configuration missing. Email not sent to {Email}", email);
                    return;
                }

                var message = new MailMessage
                {
                    From = new MailAddress(fromEmail),
                    Subject = subject,
                    Body = htmlMessage,
                    IsBodyHtml = true
                };
                message.To.Add(new MailAddress(email));

                using var client = new SmtpClient(smtpServer, smtpPort)
                {
                    Credentials = new NetworkCredential(smtpUsername, smtpPassword),
                    EnableSsl = true
                };

                await client.SendMailAsync(message);
                _logger.LogInformation("Email sent successfully to {Email}", email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email}", email);
                throw;
            }
        }
    }
}