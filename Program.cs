using System.Collections.Concurrent;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;


var builder = WebApplication.CreateBuilder(args);
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = "your-app",
            ValidAudience = "your-app",
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes("this-is-a-very-strong-secret-key-123456"))
        };
    });

builder.Services.AddAuthorization(options =>
{
options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
});

var config = builder.Configuration;
var jwtKey = config["Jwt:Key"];
var jwtIssuer = config["Jwt:Issuer"];
var jwtAudience = config["Jwt:Audience"];



var app = builder.Build();

app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";

        var error = new
        {
            status = 500,
            message = "An unexpected error occurred.",
            timestamp = DateTime.UtcNow
        };

        await context.Response.WriteAsJsonAsync(error);
    });
});


app.Use(async (context, next) =>
{
    var request = context.Request;
    Console.WriteLine($"Incoming Request: {request.Method} {request.Path}");

    await next();

    var response = context.Response;
    Console.WriteLine($"Outgoing Response: {response.StatusCode}");
});
app.UseMiddleware<ErrorHandlingMiddleware>();
app.UseMiddleware<JwtAuthenticationMiddleware>();

app.UseSwagger();
app.UseSwaggerUI();


app.UseAuthentication();
app.UseAuthorization();


app.MapPost("/token", () =>
{
    var claims = new[]
    {
        new Claim(ClaimTypes.Name, "Sajid"),
        new Claim(ClaimTypes.Role, "Admin")
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("this-is-a-very-strong-secret-key-123456"));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: "your-app",
        audience: "your-app",
        claims: claims,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: creds);

    return Results.Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
});


// In-memory store with thread-safe dictionary
var users = new ConcurrentDictionary<int, User>();
users.TryAdd(1, new User { Id = 1, Name = "Alice", Email = "alice@example.com" });
users.TryAdd(2, new User { Id = 2, Name = "Bob", Email = "bob@example.com" });
var userCredentials = new ConcurrentDictionary<string, string>(); // username → password

// Validation helper
bool IsValidUser(User user) =>
    !string.IsNullOrWhiteSpace(user.Name) &&
    !string.IsNullOrWhiteSpace(user.Email) &&
    new EmailAddressAttribute().IsValid(user.Email);

// GET: All users
app.MapGet("/users", () =>
{
    try
    {
        return Results.Ok(users.Values);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error retrieving users: {ex.Message}");
    }
}).RequireAuthorization();

// GET: User by ID
app.MapGet("/users/{id}", (int id) =>
{
    try
    {
        return users.TryGetValue(id, out var user)
            ? Results.Ok(user)
            : Results.NotFound($"User with ID {id} not found.");
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error retrieving user: {ex.Message}");
    }
}).RequireAuthorization();

// POST: Add new user
app.MapPost("/signup", (UserRegister newUser) =>
{
    if (string.IsNullOrWhiteSpace(newUser.Username) || string.IsNullOrWhiteSpace(newUser.Password))
        return Results.BadRequest("Username and password are required.");

    if (!IsValidUser(new User { Name = newUser.Name, Email = newUser.Email }))
        return Results.BadRequest("Invalid name or email.");

    if (!userCredentials.TryAdd(newUser.Username, newUser.Password))
        return Results.Conflict("Username already exists.");

    int newId = users.Keys.DefaultIfEmpty(0).Max() + 1;
    users[newId] = new User
    {
        Id = newId,
        Name = newUser.Name,
        Email = newUser.Email
    };

    return Results.Ok("User registered successfully.");
});

app.MapPost("/login", (UserLogin login) =>
{
    if (!userCredentials.TryGetValue(login.Username, out var storedPassword) || storedPassword != login.Password)
        return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(ClaimTypes.Name, login.Username),
        new Claim(ClaimTypes.Role, "User")
    };

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: creds);

    return Results.Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
});

// POST: Add new user
app.MapPost("/users", (User newUser) =>
{
    try
    {
        if (!IsValidUser(newUser))
            return Results.BadRequest("Invalid user data.");

        int newId = users.Keys.Any() ? users.Keys.Max() + 1 : 1;
        newUser.Id = newId;
        users[newId] = newUser;
        return Results.Created($"/users/{newId}", newUser);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error adding user: {ex.Message}");
    }
});


// PUT: Update user
app.MapPut("/users/{id}", (int id, User updatedUser) =>
{
    try
    {
        if (!users.ContainsKey(id))
            return Results.NotFound($"User with ID {id} not found.");

        if (!IsValidUser(updatedUser))
            return Results.BadRequest("Invalid user data.");

        updatedUser.Id = id;
        users[id] = updatedUser;
        return Results.Ok(updatedUser);
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error updating user: {ex.Message}");
    }
}).RequireAuthorization();

// DELETE: Remove user
app.MapDelete("/users/{id}", (int id) =>
{
    try
    {
        return users.TryRemove(id, out _)
            ? Results.NoContent()
            : Results.NotFound($"User with ID {id} not found.");
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error deleting user: {ex.Message}");
    }
}).RequireAuthorization();

app.Run();

// Model with optional annotations
public class User
{
    public int Id { get; set; }

    [Required]
    public string Name { get; set; } = default!;

    [Required]
    [EmailAddress]
    public string Email { get; set; } = default!;
}
public record UserLogin(string Username, string Password);
public record UserRegister(string Username, string Password, string Name, string Email);

public class ErrorHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<ErrorHandlingMiddleware> _logger;

    public ErrorHandlingMiddleware(RequestDelegate next, ILogger<ErrorHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception occurred.");

            context.Response.StatusCode = 500;
            context.Response.ContentType = "application/json";

            var errorResponse = new
            {
                error = "Internal server error.",
                details = ex.Message,
                timestamp = DateTime.UtcNow
            };

            await context.Response.WriteAsJsonAsync(errorResponse);
        }
    }
}

public class JwtAuthenticationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly string _secretKey;
    private readonly string _issuer;
    private readonly string _audience;

    public JwtAuthenticationMiddleware(RequestDelegate next, IConfiguration config)
    {
        _next = next;
        _secretKey = config["Jwt:Key"]!;
        _issuer = config["Jwt:Issuer"]!;
        _audience = config["Jwt:Audience"]!;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

        if (string.IsNullOrEmpty(token))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Unauthorized: Token is missing.");
            return;
        }

        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes(_secretKey);

        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _issuer,
                ValidateAudience = true,
                ValidAudience = _audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            // Token is valid, continue to next middleware
            await _next(context);
        }
        catch (Exception)
        {
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync("{\"error\": \"Unauthorized: Invalid or expired token.\"}");
        }
    }
}
