using GestionDeUsuarioAPI.DB;
using GestionDeUsuarioAPI.Services;
using GestionDeUsuarioAPI.Services.UsuariosServices;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Aqui configuro JWT
var jwtSettings = builder.Configuration.GetSection("JwtSettings");

builder.Services.AddDbContext<ContextDB>(op =>
{
    op.UseSqlServer(builder.Configuration.GetConnectionString("ItlaUser"));
});

// Todo lo de seervicios
builder.Services.AddScoped<IUsuarioService, UsuarioService>();

//  Controladores y Swagger
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "GestionDeUsuarioAPI", Version = "v1" });

    // Autenticacion del Swagger para el JWT
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Introduce el token en el siguiente formato: Bearer {token}"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = "JwtCustomScheme";
    options.DefaultChallengeScheme = "JwtCustomScheme";
})
.AddScheme<AuthenticationSchemeOptions, Autenticacion>("JwtCustomScheme", null);

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication(); 
app.UseAuthorization();
app.MapControllers();

app.Run();
