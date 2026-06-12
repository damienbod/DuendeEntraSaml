using IdentityProvider.Data;
using IdentityProvider.Models;
using IdentityProvider.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using NetEscapades.AspNetCore.SecurityHeaders.Infrastructure;
using Serilog;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;

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
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients(shopclientUIUrl!, adminclientUIUrl!))
            .AddAspNetIdentity<ApplicationUser>();

        builder.Services.AddDistributedMemoryCache();

        var samlTenantId = builder.Configuration["Saml:TenantId"] ?? builder.Configuration["Saml:TenantId"];
        var samlMetadataLocation = builder.Configuration["Saml:MetadataLocation"]
            ?? $"https://login.microsoftonline.com/{samlTenantId}/federationmetadata/2007-06/federationmetadata.xml";
        var samlIdpEntityId = builder.Configuration["Saml:IdpEntityId"]
            ?? $"https://sts.windows.net/{samlTenantId}/";
        var samlSpEntityId = builder.Configuration["Saml:SpEntityId"] ?? "https://localhost:5021/Saml2";
        var samlReturnUrl = builder.Configuration["Saml:ReturnUrl"] ?? "https://localhost:5021/";

        // https://docs.duendesoftware.com/identityserver/ui/login/saml-provider/
        // https://learn.microsoft.com/en-us/entra/identity/saas-apps/saml-toolkit-tutorial
        // https://github.com/Sustainsys/Saml2
        builder.Services.AddAuthentication()
             .AddSaml2("entra-saml-idp", options =>
             {
                 options.SPOptions.EntityId = new EntityId(samlSpEntityId);
                 options.SPOptions.ReturnUrl = new Uri(samlReturnUrl);

                 var idp = new Sustainsys.Saml2.IdentityProvider(
                     new EntityId(samlIdpEntityId), options.SPOptions)
                 {
                     MetadataLocation = samlMetadataLocation,
                     LoadMetadata = true,
                     //AllowUnsolicitedAuthnResponse = true
                 };

                //TryAddConfiguredSigningKeysFromMetadata(idp, samlMetadataLocation);

                 options.IdentityProviders.Add(idp);
             });

        //.AddSamlServiceProvider("entra-saml-idp", options =>
        //{
        //    //options.SignInScheme = "Identity.External";
        //    options.SpEntityId = "https://sts.windows.net/7ff95b15-dc21-4ba6-bc92-824856578fc1/";
        //    options.IdpEntityId = "https://sts.windows.net/7ff95b15-dc21-4ba6-bc92-824856578fc1/";
        //    options.SingleSignOnServiceUrl = "https://login.microsoftonline.com/7ff95b15-dc21-4ba6-bc92-824856578fc1/saml2";
        //    options.SigningCertificatesBase64 = [ base64Cert ];

        //});

        builder.Services.AddAuthentication()
            .AddMicrosoftIdentityWebApp(options =>
            {
                builder.Configuration.Bind("AzureAd", options);
                options.SignInScheme = "entraidcookie";
                options.UsePkce = true;
                options.Events = new OpenIdConnectEvents
                {
                    OnTokenResponseReceived = context =>
                    {
                        var idToken = context.TokenEndpointResponse.IdToken;
                        return Task.CompletedTask;
                    }
                };
            }, copt => { }, "EntraID", "entraidcookie", false, "Entra ID")
            .EnableTokenAcquisitionToCallDownstreamApi(["User.Read"])
            .AddMicrosoftGraph()
            .AddDistributedTokenCaches();

        builder.Services.AddAuthentication()
            .AddMicrosoftIdentityWebApp(options =>
            {
                builder.Configuration.Bind("EntraIDAdmin", options);
                options.SignInScheme = "adminentraidcookie";
                options.UsePkce = true;
                options.Events = new OpenIdConnectEvents
                {
                    OnTokenResponseReceived = context =>
                    {
                        var idToken = context.TokenEndpointResponse.IdToken;
                        return Task.CompletedTask;
                    }
                };
            }, copt => { }, "AdminEntraID", "adminentraidcookie", false, "Admin ME-ID")
            .EnableTokenAcquisitionToCallDownstreamApi(["User.Read"])
            .AddMicrosoftGraph()
            .AddDistributedTokenCaches();

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

        app.MapGet("/login/entra-saml", async (HttpContext context) =>
        {
            await context.ChallengeAsync("entra-saml-idp", new AuthenticationProperties
            {
                RedirectUri = "/" // where to go after successful login
            });
        });

        app.MapControllers();
        return app;
    }

    private static void TryAddConfiguredSigningKeysFromMetadata(Sustainsys.Saml2.IdentityProvider idp, string metadataLocation)
    {
        try
        {
            var metadata = XDocument.Load(metadataLocation);
            XNamespace md = "urn:oasis:names:tc:SAML:2.0:metadata";
            XNamespace ds = "http://www.w3.org/2000/09/xmldsig#";

            var signingCerts = metadata
                .Descendants(md + "IDPSSODescriptor")
                .Descendants(md + "KeyDescriptor")
                .Where(k =>
                {
                    var use = (string?)k.Attribute("use");
                    return string.IsNullOrWhiteSpace(use) || use.Equals("signing", StringComparison.OrdinalIgnoreCase);
                })
                .Descendants(ds + "X509Certificate")
                .Select(c => c.Value?.Trim())
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .Distinct(StringComparer.Ordinal);

            foreach (var signingCert in signingCerts)
            {
                var cert = X509CertificateLoader.LoadCertificate(Convert.FromBase64String(signingCert!));
                idp.SigningKeys.AddConfiguredKey(cert);
            }
        }
        catch (Exception ex)
        {
            Log.Warning(ex, "Failed to pre-load SAML metadata signing keys from {MetadataLocation}", metadataLocation);
        }
    }
}