using Duende.IdentityServer.Models;
using IdentityProvider.Data;
using IdentityProvider.Models;
using IdentityProvider.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web.UI;
using NetEscapades.AspNetCore.SecurityHeaders.Infrastructure;
using Serilog;

namespace IdentityProvider;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddRazorPages()
            .AddMicrosoftIdentityUI();
        builder.Services.AddScoped<MsGraphDelegatedService>();

        builder.Services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

        builder.Services.Configure<EmailSettings>(builder.Configuration.GetSection("EmailSettings"));
        builder.Services.AddTransient<IEmailSender, EmailSender>();

        builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        var shopclientUIUrl = builder.Configuration["ShopClientUIUrl"];
        var adminclientUIUrl = builder.Configuration["AdminClientUIUrl"];
        builder.Services
            .AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/
                options.EmitStaticAudienceClaim = true;
            })
            .AddSaml()
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients(shopclientUIUrl!, adminclientUIUrl!))
            .AddInMemorySamlServiceProviders(
            [
                new SamlServiceProvider
                {
                    EntityId = "YOUR_HUBSPOT_AUDIENCE_URI",
                    DisplayName = "HubSpot",

                    // The ACS URL from HubSpot's SSO settings
                    AssertionConsumerServiceUrls =
                    [
                        new IndexedEndpoint
                        {
                            Location = "YOUR_HUBSPOT_ACS_URL",
                            Binding = SamlBinding.HttpPost,
                            Index = 0,
                            IsDefault = true
                        }
                    ],

                    // HubSpot requires email-format NameID
                    DefaultNameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",

                    // Sign the assertion (HubSpot requirement)
                    SigningBehavior = SamlSigningBehavior.SignAssertion,

                    // Identity resources available for this SP
                    AllowedScopes = ["openid", "email", "profile"],
                }
            ])
            .AddAspNetIdentity<ApplicationUser>();

        builder.Services.AddDistributedMemoryCache();

        //builder.Services.AddAuthentication()
        //    .AddMicrosoftIdentityWebApp(options =>
        //    {
        //        builder.Configuration.Bind("AzureAd", options);
        //        options.SignInScheme = "entraidcookie";
        //        options.UsePkce = true;
        //        options.Events = new OpenIdConnectEvents
        //        {
        //            OnTokenResponseReceived = context =>
        //            {
        //                var idToken = context.TokenEndpointResponse.IdToken;
        //                return Task.CompletedTask;
        //            }
        //        };
        //    }, copt => { }, "EntraID", "entraidcookie", false, "Entra ID")
        //    .EnableTokenAcquisitionToCallDownstreamApi(["User.Read"])
        //    .AddMicrosoftGraph()
        //    .AddDistributedTokenCaches();

        //builder.Services.AddAuthentication()
        //    .AddMicrosoftIdentityWebApp(options =>
        //    {
        //        builder.Configuration.Bind("EntraIDAdmin", options);
        //        options.SignInScheme = "adminentraidcookie";
        //        options.UsePkce = true;
        //        options.Events = new OpenIdConnectEvents
        //        {
        //            OnTokenResponseReceived = context =>
        //            {
        //                var idToken = context.TokenEndpointResponse.IdToken;
        //                return Task.CompletedTask;
        //            }
        //        };
        //    }, copt => { }, "AdminEntraID", "adminentraidcookie", false, "Admin ME-ID")
        //    .EnableTokenAcquisitionToCallDownstreamApi(["User.Read"])
        //    .AddMicrosoftGraph()
        //    .AddDistributedTokenCaches();

        builder.Services.AddAuthentication()
            .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
             {
                 var oauthConfig = builder.Configuration.GetSection("ProfileApiConfigurations");
                 options.Authority = oauthConfig["Authority"];
                 options.Audience = oauthConfig["Audience"];
                 options.MapInboundClaims = false;
                 options.TokenValidationParameters.ValidTypes = ["at+jwt"];
             });

        builder.Services.AddControllers();

        builder.Services.AddSecurityHeaderPolicies()
          .SetPolicySelector((PolicySelectorContext ctx) =>
          {
              // Weakened security headers for IDP callback
              if (ctx.HttpContext.Request.Path.StartsWithSegments("/connect"))
              {
                  return SecurityHeadersDefinitionsWeakened.GetHeaderPolicyCollection(
                      builder.Environment.IsDevelopment(),
                      builder.Configuration["AzureAd:Instance"],
                      builder.Configuration["ShopClientUIUrl"]!,
                      builder.Configuration["AdminClientUIUrl"]!);
              }

              return SecurityHeadersDefinitions.GetHeaderPolicyCollection(
                  builder.Environment.IsDevelopment(),
                  builder.Configuration["AzureAd:Instance"],
                  builder.Configuration["ShopClientUIUrl"]!,
                  builder.Configuration["AdminClientUIUrl"]!);
          });

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        app.UseSecurityHeaders();

        app.UseStaticFiles();
        app.UseRouting();
        app.UseIdentityServer();
        app.UseAuthorization();

        app.MapRazorPages()
            .RequireAuthorization();

        app.MapControllers();
        return app;
    }
}