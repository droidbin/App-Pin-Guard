using System.Runtime.Serialization.Json;
using Xunit;

namespace UnitTests;

public sealed class PinHashTests
{
    [Fact]
    public void Create_And_Verify_Succeeds_For_Matching_Pin()
    {
        var record = PinHash.Create("123456");

        Assert.True(record.IsSet);
        Assert.True(PinHash.Verify("123456", record));
        Assert.False(PinHash.Verify("654321", record));
        Assert.False(PinHash.Verify("12345", record));
    }

    [Fact]
    public void Create_Uses_Unique_Salt_And_Version_Per_Call()
    {
        var first = PinHash.Create("246810");
        var second = PinHash.Create("246810");

        Assert.NotEqual(first.Salt, second.Salt);
        Assert.NotEqual(first.Hash, second.Hash);
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
        Assert.False(PinHash.Verify(pin, new PinRecord { Salt = salt, Hash = hash }));
    }
}

public sealed class PolicyModelTests
{
    [Fact]
    public void Deserialization_Applies_The_Same_Defaults_As_The_Constructor()
    {
        var serializer = new DataContractJsonSerializer(typeof(PolicyDocument));
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("{\"Revision\":4}"));
        var policy = (PolicyDocument)serializer.ReadObject(stream)!;

        Assert.Equal(PolicyDocument.CurrentSchemaVersion, policy.SchemaVersion);
        Assert.Equal(4, policy.Revision);
        Assert.True(policy.EnableLaunchGate);
        Assert.False(policy.CloseAppsOnLock);
        Assert.NotNull(policy.Apps);
    }

    [Fact]
    public void App_Pins_Are_Keyed_By_App_Id()
    {
        var secrets = new SecretsDocument();
        secrets.SetAppPin("a", PinHash.Create("1111"));
        secrets.SetAppPin("b", PinHash.Create("2222"));
        secrets.SetAppPin("a", PinHash.Create("3333"));

        Assert.Equal(2, secrets.AppPins.Count);
        Assert.True(PinHash.Verify("3333", secrets.FindAppPin("a")));
        Assert.False(PinHash.Verify("1111", secrets.FindAppPin("a")));
        secrets.RemoveAppPin("a");
        Assert.Null(secrets.FindAppPin("a"));
    }
}

public sealed class PolicyRulesTests
{
    [Theory]
    [InlineData("chrome.exe", "window")]
    [InlineData("KakaoTalk.exe", "launch")]
    public void Mode_Follows_The_Browser_List(string executable, string expected)
    {
        var app = new AppPolicy { ExecutableName = executable, Path = @"C:\apps\" + executable };

        Assert.Equal(expected, PolicyRules.GetMode(app));
    }

    [Fact]
    public void Packaged_Apps_Use_Window_Mode()
    {
        Assert.Equal("window", PolicyRules.GetMode(new AppPolicy { IsPackaged = true, ExecutableName = "x.exe" }));
    }

    [Theory]
    [InlineData(9, 0, true)]
    [InlineData(20, 0, false)]
    [InlineData(3, 0, false)]
    public void Lock_Hours_Handle_Same_Day_Ranges(int hour, int minute, bool locked)
    {
        var launch = new LaunchPolicy { LockStartMinute = 8 * 60, LockEndMinute = 18 * 60 };

        Assert.Equal(locked, PolicyRules.IsWithinLockHours(launch, new DateTime(2026, 1, 1, hour, minute, 0)));
    }

    [Theory]
    [InlineData(23, true)]
    [InlineData(2, true)]
    [InlineData(12, false)]
    public void Lock_Hours_Handle_Ranges_Across_Midnight(int hour, bool locked)
    {
        var launch = new LaunchPolicy { LockStartMinute = 22 * 60, LockEndMinute = 6 * 60 };

        Assert.Equal(locked, PolicyRules.IsWithinLockHours(launch, new DateTime(2026, 1, 1, hour, 0, 0)));
    }
}

public sealed class GateSpoolTests
{
    [Fact]
    public void Request_Round_Trips()
    {
        var request = new GateRequest { Op = GateSpool.OpAuthorize, Pid = 4242, Path = @"C:\한글 폴더\app.exe", Pin = "1234" };

        var parsed = GateRequest.Parse(request.Serialize());

        Assert.NotNull(parsed);
        Assert.Equal(request.Nonce, parsed!.Nonce);
        Assert.Equal(4242, parsed.Pid);
        Assert.Equal(request.Path, parsed.Path);
        Assert.Equal("1234", parsed.Pin);
    }

    [Fact]
    public void Track_Request_Carries_The_Child_Pid()
    {
        var request = new GateRequest { Op = GateSpool.OpTrack, Pid = 10, Path = @"C:\a.exe", Child = 77 };

        Assert.Equal(77, GateRequest.Parse(request.Serialize())!.Child);
    }

    [Fact]
    public void Unlock_Request_Carries_The_Target_Pid()
    {
        var request = new GateRequest { Op = GateSpool.OpUnlock, Pid = 10, Path = @"C:\Chrome\chrome.exe", Child = 321 };

        var parsed = GateRequest.Parse(request.Serialize());

        Assert.NotNull(parsed);
        Assert.Equal(GateSpool.OpUnlock, parsed!.Op);
        Assert.Equal(321, parsed.Child);
    }

    [Theory]
    [InlineData("")]
    [InlineData("garbage")]
    [InlineData("WAP-GATE 1\nop=authorize\nnonce=short\npid=1\npath=\n")]
    [InlineData("WAP-GATE 1\nop=delete\nnonce=00000000000000000000000000000000\npid=1\npath=\n")]
    public void Malformed_Requests_Are_Rejected(string text)
    {
        Assert.Null(GateRequest.Parse(text));
    }

    [Fact]
    public void Response_Round_Trips()
    {
        var response = new GateResponse { Nonce = GateSpool.NewNonce(), Result = GateSpool.ResultRateLimited, RetryAfterSeconds = 30 };

        var parsed = GateResponse.Parse(response.Serialize());

        Assert.NotNull(parsed);
        Assert.Equal(GateSpool.ResultRateLimited, parsed!.Result);
        Assert.Equal(30, parsed.RetryAfterSeconds);
    }
}

public sealed class EnforcementFileTests
{
    [Fact]
    public void Round_Trips_All_Line_Types()
    {
        var data = new EnforcementData { Revision = 9 };
        data.HidePaths.Add(@"C:\Program Files\Google\Chrome\chrome.exe");
        data.HidePackages.Add("Contoso.App_8wekyb3d8bbwe");
        data.HideBefore.Add(new KeyValuePair<string, long>(@"C:\apps\한글.exe", 638000000000000000));
        data.Close.Add(@"C:\apps\한글.exe");
        data.Granted.Add(new KeyValuePair<int, long>(123, 638000000000000001));

        var parsed = EnforcementData.Parse(data.Serialize());

        Assert.Equal(9, parsed.Revision);
        Assert.Equal(data.HidePaths, parsed.HidePaths);
        Assert.Equal(data.HidePackages, parsed.HidePackages);
        Assert.Equal(data.HideBefore, parsed.HideBefore);
        Assert.Equal(data.Close, parsed.Close);
        Assert.Equal(data.Granted, parsed.Granted);
    }

    [Theory]
    [InlineData("")]
    [InlineData("WAP-ENF 1\nW:!!!\nrev=1\n")]
    [InlineData("WAP-ENF 1\nX:AAAA\nrev=1\n")]
    [InlineData("WAP-ENF 1\nW:AAAA\n")]
    public void Malformed_Files_Are_Rejected(string text)
    {
        Assert.Throws<FormatException>(() => EnforcementData.Parse(text));
    }
}
