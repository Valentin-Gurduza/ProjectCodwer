using Twilio;
using Twilio.Rest.Api.V2010.Account;

namespace ProjectCodwer.Services
{
    public class SmsService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<SmsService> _logger;

        public SmsService(IConfiguration configuration, ILogger<SmsService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SendSmsAsync(string phoneNumber, string message)
        {
            try
            {
                var accountSid = _configuration["Twilio:AccountSid"];
                var authToken = _configuration["Twilio:AuthToken"];
                var fromNumber = _configuration["Twilio:PhoneNumber"];

                if (string.IsNullOrEmpty(accountSid) || string.IsNullOrEmpty(authToken))
                {
                    _logger.LogWarning("Twilio configuration missing. SMS not sent to {PhoneNumber}", phoneNumber);
                    return;
                }

                TwilioClient.Init(accountSid, authToken);
                
                var smsMessage = await MessageResource.CreateAsync(
                    body: message,
                    from: new Twilio.Types.PhoneNumber(fromNumber),
                    to: new Twilio.Types.PhoneNumber(phoneNumber)
                );
                
                _logger.LogInformation("SMS sent successfully to {PhoneNumber}, SID: {Sid}", 
                    phoneNumber, smsMessage.Sid);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send SMS to {PhoneNumber}", phoneNumber);
                throw;
            }
        }
    }
}