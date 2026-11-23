using WindowsAppProtector.Services;
using Xunit;

namespace UnitTests;

public sealed class PinHasherTests
{
    [Fact]
    public void CreateHash_And_Verify_Succeeds_For_Matching_Pin()
    {
        var (salt, hash) = PinHasher.CreateHash("123456");

        Assert.False(string.IsNullOrWhiteSpace(salt));
        Assert.False(string.IsNullOrWhiteSpace(hash));
        Assert.True(PinHasher.Verify("123456", salt, hash));
    }

    [Fact]
    public void CreateHash_Uses_Unique_Salt_Per_Call()
    {
        var first = PinHasher.CreateHash("246810");
        var second = PinHasher.CreateHash("246810");

        Assert.NotEqual(first.Salt, second.Salt);
        Assert.NotEqual(first.Hash, second.Hash);
    }

    [Fact]
    public void Verify_Returns_False_For_Wrong_Pin()
    {
        var (salt, hash) = PinHasher.CreateHash("123456");

        Assert.False(PinHasher.Verify("654321", salt, hash));
        Assert.False(PinHasher.Verify("12345", salt, hash));
    }

    [Theory]
    [InlineData("", "c2FsdA==", "aGFzaA==")]
    [InlineData("   ", "c2FsdA==", "aGFzaA==")]
    [InlineData("1234", "", "aGFzaA==")]
    [InlineData("1234", "c2FsdA==", "")]
    [InlineData("1234", "not-valid-base64!!!", "aGFzaA==")]
    [InlineData("1234", "c2FsdA==", "not-valid-base64!!!")]
    public void Verify_Returns_False_For_Invalid_Inputs(string pin, string salt, string hash)
    {
        Assert.False(PinHasher.Verify(pin, salt, hash));
    }
}
