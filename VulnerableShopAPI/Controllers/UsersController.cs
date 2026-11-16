using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace VulnerableShopAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        // False Positive Trap: Dummy non-sensitive configuration key
        // Static analysis tools (SAST) often flag any variable named "ApiKey" or "Secret" as a hardcoded credential leak.
        private const string PublicSandboxApiKey = "SANDBOX_PUBLIC_READONLY_KEY_0000";

        // 1. TRUE POSITIVE: Reflected Cross-Site Scripting (XSS)
        // Returns raw user input directly as HTML without encoding.
        [HttpGet("welcome")]
        public ContentResult WelcomeUser([FromQuery] string username)
        {
            var htmlResponse = $"<html><body><h1>Welcome back, {username}!</h1></body></html>";
            return Content(htmlResponse, "text/html");
        }

        // 2. TRUE POSITIVE: Broken Access Control / IDOR (Insecure Direct Object Reference)
        // Allows anyone to fetch any user's private profile without authentication or ownership check.
        [HttpGet("{userId}/profile")]
        public IActionResult GetUserProfile(int userId)
        {
            var mockProfiles = new Dictionary<int, object>
            {
                { 1, new { Id = 1, Role = "Admin", Email = "admin@vulnerableshop.local", ApiQuota = 9999 } },
                { 2, new { Id = 2, Role = "Customer", Email = "student@dogus.edu.tr", ApiQuota = 50 } }
            };

            if (!mockProfiles.ContainsKey(userId))
            {
                return NotFound(new { Message = "User not found" });
            }

            // Uses the vulnerable Newtonsoft.Json 12.0.3 package
            var serialized = JsonConvert.SerializeObject(mockProfiles[userId]);
            return Ok(serialized);
        }

        // 3. FALSE POSITIVE TRAP: Safe redirect endpoint
        // Uses a strict allowlist, so Open Redirect scanners should not flag it, though naive SAST rules might.
        [HttpGet("redirect")]
        public IActionResult SafeRedirect([FromQuery] string target)
        {
            var allowedPaths = new HashSet<string> { "/home", "/products", "/about" };

            if (string.IsNullOrEmpty(target) || !allowedPaths.Contains(target))
            {
                return BadRequest(new { Error = "Invalid redirect target", KeyUsed = PublicSandboxApiKey });
            }

            return Redirect(target);
        }
    }
}