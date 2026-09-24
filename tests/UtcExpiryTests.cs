using Aiursoft.S360.Services;

namespace Aiursoft.S360.Tests;

[TestClass]
public class UtcExpiryTests
{
    [TestMethod]
    public void HtmlDateTimeWithoutOffsetIsInterpretedAsUtc()
    {
        var input = new DateTime(2026, 10, 1, 12, 30, 0, DateTimeKind.Unspecified);
        var result = UtcExpiry.Normalize(input);
        Assert.AreEqual(DateTimeKind.Utc, result.Kind);
        Assert.AreEqual(input.Ticks, result.Ticks);
    }

    [TestMethod]
    public void DateTimeWithExplicitKindKeepsTheSameInstant()
    {
        var utc = new DateTime(2026, 10, 1, 12, 30, 0, DateTimeKind.Utc);
        Assert.AreEqual(utc, UtcExpiry.Normalize(utc));
        Assert.AreEqual(utc, UtcExpiry.Normalize(utc.ToLocalTime()));
    }
}
