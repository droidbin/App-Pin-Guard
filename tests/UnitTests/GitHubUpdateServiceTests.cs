using WindowsAppProtector.Services;
using Xunit;

namespace UnitTests;

public sealed class GitHubUpdateServiceTests
{
    [Theory]
    [InlineData("v2.0.0", 2, 0, 0)]
    [InlineData("2.0.0", 2, 0, 0)]
    [InlineData("  V2.1.3  ", 2, 1, 3)]
    [InlineData("v2.0.0-beta.6", 2, 0, 0)]
    [InlineData("2.0.0-beta.6+sha.abc123", 2, 0, 0)]
    public void TryParseVersion_Parses_Valid_Tags(string tag, int major, int minor, int build)
    {
        var ok = GitHubUpdateService.TryParseVersion(tag, out var version);

        Assert.True(ok);
        Assert.Equal(new Version(major, minor, build), version);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("v")]
    [InlineData("not-a-version")]
    public void TryParseVersion_Rejects_Invalid_Tags(string tag)
    {
        Assert.False(GitHubUpdateService.TryParseVersion(tag, out _));
    }

    [Fact]
    public void NormalizeVersion_Fills_Unset_Components_With_Zero()
    {
        Assert.Equal(new Version(2, 0, 0, 0), GitHubUpdateService.NormalizeVersion(new Version(2, 0)));
        Assert.Equal(new Version(2, 1, 3, 0), GitHubUpdateService.NormalizeVersion(new Version(2, 1, 3)));
    }

    [Fact]
    public void IsNewerRelease_Treats_Prerelease_As_Older_Than_Stable_Of_Same_Version()
    {
        Assert.True(GitHubUpdateService.TryParseVersion("v2.0.0-beta.6", out var betaVersion));
        Assert.True(GitHubUpdateService.TryParseVersion("v2.0.0", out var stableVersion));

        Assert.True(GitHubUpdateService.IsNewerRelease(stableVersion, betaVersion, isCurrentPrerelease: true));
        Assert.False(GitHubUpdateService.IsNewerRelease(stableVersion, stableVersion, isCurrentPrerelease: false));
    }

    [Fact]
    public void IsNewerRelease_Compares_Higher_And_Lower_Versions()
    {
        Assert.True(GitHubUpdateService.IsNewerRelease(new Version(2, 1, 0), new Version(2, 0, 0), isCurrentPrerelease: false));
        Assert.False(GitHubUpdateService.IsNewerRelease(new Version(1, 9, 9), new Version(2, 0, 0), isCurrentPrerelease: false));
        Assert.False(GitHubUpdateService.IsNewerRelease(new Version(1, 9, 9), new Version(2, 0, 0), isCurrentPrerelease: true));
    }
}
