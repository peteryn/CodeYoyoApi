using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            }
        };
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.None;
    });

builder.Services.AddAuthorization();

const string corsPolicy = "_myAllowSpecificOrigins";

builder.Services.AddCors(options =>
{
    options.AddPolicy(name: corsPolicy,
        builder =>
        {
            builder
                .WithOrigins("http://localhost:3000")
                .AllowCredentials()
                .AllowAnyHeader()
                .AllowAnyMethod();
        });
});

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//app.UseHttpsRedirection();
// put routes here
app.UseRouting();

app.MapPost("/signin", async (HttpContext context) =>
{
    string authHeader = context.Request.Headers.Authorization.ToString();
    string jwt = authHeader.ToString().Replace("Bearer ", "");
    try
    {
        var payload = await GoogleJsonWebSignature.ValidateAsync(jwt, new GoogleJsonWebSignature.ValidationSettings());
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Email, payload.Email),
            new Claim(ClaimTypes.Name, payload.Name),
            new Claim(ClaimTypes.NameIdentifier, payload.Subject)
        };

        var claimsIdentity = new ClaimsIdentity(
           claims, CookieAuthenticationDefaults.AuthenticationScheme);

        var authProperties = new AuthenticationProperties
        {
            ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1),
            IsPersistent = true,  // This is crucial - without it, it becomes a session cookie
            IssuedUtc = DateTimeOffset.UtcNow,
        };
        await context.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(claimsIdentity),
            authProperties);

        return Results.Ok();
    }
    catch (InvalidJwtException)
    {
        return Results.Unauthorized();
    }
});

app.MapGet("/secure", () => new { message = "Message From Server" }).RequireAuthorization();

app.MapGet("/easy", () => new { message = "cool" });

app.UseCors(corsPolicy);
app.UseAuthentication();
app.UseAuthorization();

app.Run();
