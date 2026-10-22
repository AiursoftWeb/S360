using Aiursoft.S360.Models;

namespace Aiursoft.S360.Configuration;

public class SettingsMap
{
    public const string ProjectName = "ProjectName";
    public const string BrandName = "BrandName";
    public const string BrandHomeUrl = "BrandHomeUrl";
    public const string ProjectLogo = "ProjectLogo";
    public const string AllowUserAdjustNickname = "Allow_User_Adjust_Nickname";
    public const string Icp = "Icp";
    public const string DummyNumber = "DummyNumber";
    public const string DummyChoice = "DummyChoice";
    public const string AlertCenterEnabled = "AlertCenter_Enabled";
    public const string AlertCenterEndpoint = "AlertCenter_Endpoint";
    public const string AlertCenterApiKey = "AlertCenter_ApiKey";
    public const string AlertCenterPublicBaseUrl = "AlertCenter_PublicBaseUrl";
    public const string AlertCenterAutoMitigate = "AlertCenter_AutoMitigate";
    public const string AllowAnonymousReview = "AllowAnonymousReview";

    public class FakeLocalizer
    {
        public string this[string name] => name;
    }

    private static readonly FakeLocalizer Localizer = new();

    public static readonly List<GlobalSettingDefinition> Definitions = new()
    {
        new GlobalSettingDefinition
        {
            Key = AlertCenterEnabled,
            Name = Localizer["Enable AlertCenter integration"],
            Description = Localizer["Report confirmed security findings from company production baselines."],
            Type = SettingType.Bool,
            DefaultValue = "False"
        },
        new GlobalSettingDefinition
        {
            Key = AlertCenterEndpoint,
            Name = Localizer["AlertCenter endpoint"],
            Description = Localizer["HTTP(S) base URL of AlertCenter."],
            Type = SettingType.Text,
            DefaultValue = "https://alertcenter.aiursoft.com"
        },
        new GlobalSettingDefinition
        {
            Key = AlertCenterApiKey,
            Name = Localizer["AlertCenter application API key"],
            Description = Localizer["Dedicated application key with query, create, metadata patch and mitigate permissions."],
            Type = SettingType.Secret,
            DefaultValue = ""
        },
        new GlobalSettingDefinition
        {
            Key = AlertCenterPublicBaseUrl,
            Name = Localizer["S360 public base URL"],
            Description = Localizer["Public S360 base URL used in incident links."],
            Type = SettingType.Text,
            DefaultValue = "https://s360.aiursoft.com"
        },
        new GlobalSettingDefinition
        {
            Key = AlertCenterAutoMitigate,
            Name = Localizer["Automatically mitigate recovered security incidents"],
            Description = Localizer["Mitigate only when the complete production baseline is confirmed compliant. Final resolution remains manual."],
            Type = SettingType.Bool,
            DefaultValue = "True"
        },
        new GlobalSettingDefinition
        {
            Key = ProjectName,
            Name = Localizer["Project Name"],
            Description = Localizer["The name of the project displayed in the frontend."],
            Type = SettingType.Text,
            DefaultValue = "S360"
        },
        new GlobalSettingDefinition
        {
            Key = BrandName,
            Name = Localizer["Brand Name"],
            Description = Localizer["The brand name displayed in the footer."],
            Type = SettingType.Text,
            DefaultValue = "Aiursoft"
        },
        new GlobalSettingDefinition
        {
            Key = BrandHomeUrl,
            Name = Localizer["Brand Home URL"],
            Description = Localizer[" The link to the brand's home page."],
            Type = SettingType.Text,
            DefaultValue = "https://www.aiursoft.com/"
        },
        new GlobalSettingDefinition
        {
            Key = ProjectLogo,
            Name = Localizer["Project Logo"],
            Description = Localizer["The logo of the project displayed in the navbar and footer. Support jpg, png, svg."],
            Type = SettingType.File,
            DefaultValue = "",
            Subfolder = "project-logo",
            AllowedExtensions = "jpg png svg",
            MaxSizeInMb = 5
        },
        new GlobalSettingDefinition
        {
            Key = AllowUserAdjustNickname,
            Name = Localizer["Allow User Adjust Nickname"],
            Description = Localizer["Allow users to adjust their nickname in the profile management page."],
            Type = SettingType.Bool,
            DefaultValue = "True"
        },
        new GlobalSettingDefinition
        {
            Key = Icp,
            Name = Localizer["ICP Number"],
            Description = Localizer["The ICP license number for China mainland users. Leave empty to hide."],
            Type = SettingType.Text,
            DefaultValue = ""
        },
        new GlobalSettingDefinition
        {
            Key = AllowAnonymousReview,
            Name = Localizer["Allow anonymous review"],
            Description = Localizer["Allow dependency reviews without an API key. Anonymous reviews are recorded as unverified reports and never update production usage. Baseline reports always require their protected credential."],
            Type = SettingType.Bool,
            DefaultValue = "False"
        },
        new GlobalSettingDefinition
        {
            Key = DummyNumber,
            Name = Localizer["Dummy Number"],
            Description = Localizer["A dummy number for testing."],
            Type = SettingType.Number,
            DefaultValue = "0"
        },
        new GlobalSettingDefinition
        {
            Key = DummyChoice,
            Name = Localizer["Dummy Choice"],
            Description = Localizer["A dummy choice for testing."],
            Type = SettingType.Choice,
            DefaultValue = "A",
            ChoiceOptions = new Dictionary<string, string>
            {
                { "A", "Option A" },
                { "B", "Option B" }
            }
        }
    };
}
