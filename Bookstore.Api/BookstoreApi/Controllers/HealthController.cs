using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;

namespace Bookstore.Api.Controllers
{
    [ApiController]
    [Route("health")]
    public class HealthController : ControllerBase
    {
        private static readonly DateTime _startTime = DateTime.UtcNow;

        [HttpGet]
        [SwaggerOperation(
            Summary = "Health check",
            Description = "Returns API status, version, build time, uptime. Does not require authentication."
        )]
        [SwaggerResponse(200, "Service is running")]
        public IActionResult Health()
        {
            var response = new
            {
                status = "OK",
                version = GetAppVersion(),
                build_time = GetBuildTimestamp(),
                uptime_seconds = (DateTime.UtcNow - _startTime).TotalSeconds,
            };

            return Ok(response);
        }

        private string GetAppVersion()
        {
            return typeof(HealthController).Assembly?.GetName()?.Version?.ToString() ?? "1.0.0";
        }

        private string GetBuildTimestamp()
        {
            var location = typeof(HealthController).Assembly?.Location;

            if (string.IsNullOrEmpty(location))
                return "unknown";

            return System.IO.File.GetLastWriteTime(location).ToString("yyyy-MM-dd HH:mm:ss");
        }
    }
}
