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
    public void Unlock_Request_Names_The_App_Not_A_Process()
    {
        string appId = Guid.NewGuid().ToString("N");
        var request = new GateRequest { Op = GateSpool.OpUnlock, Pid = 10, AppId = appId, Pin = "1234" };

        var parsed = GateRequest.Parse(request.Serialize());

        Assert.NotNull(parsed);
        Assert.Equal(GateSpool.OpUnlock, parsed!.Op);
        Assert.Equal(appId, parsed.AppId);
        Assert.Equal("1234", parsed.Pin);
    }

    [Theory]
    [InlineData("WAP-GATE 1\nop=unlock\nnonce=00000000000000000000000000000000\npid=1\npath=\n")]
    [InlineData("WAP-GATE 1\nop=unlock\nnonce=00000000000000000000000000000000\npid=1\npath=\napp=not-a-guid\n")]
    [InlineData("WAP-GATE 1\nop=track\nnonce=00000000000000000000000000000000\npid=1\npath=\nchild=5\n")]
    public void Unlock_Without_A_Valid_App_And_The_Removed_Track_Op_Are_Rejected(string text)
    {
        Assert.Null(GateRequest.Parse(text));
    }

    [Fact]
    public void Unlock_Request_Carries_The_Group_Of_Apps()
    {
        string first = Guid.NewGuid().ToString("N"), second = Guid.NewGuid().ToString("N"), third = Guid.NewGuid().ToString("N");
        var request = new GateRequest { Op = GateSpool.OpUnlock, Pid = 4, AppId = first, Pin = "1" };
        request.GroupIds.Add(second);
        request.GroupIds.Add(third);

        var parsed = GateRequest.Parse(request.Serialize())!;

        Assert.Equal(new[] { second, third }, parsed.GroupIds.ToArray());
    }

    [Fact]
    public void A_Malformed_Group_Is_Rejected()
    {
        string app = Guid.NewGuid().ToString("N");
        string text = "WAP-GATE 1\nop=unlock\nnonce=00000000000000000000000000000000\npid=1\npath=\napp=" + app + "\ngroup=" + app + ",nope\n";

        Assert.Null(GateRequest.Parse(text));
    }

    [Fact]
    public void Response_Carries_The_App_Id()
    {
        string appId = Guid.NewGuid().ToString("N");
        var response = new GateResponse { Nonce = GateSpool.NewNonce(), Result = GateSpool.ResultPrompt, AppId = appId };

        Assert.Equal(appId, GateResponse.Parse(response.Serialize())!.AppId);
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
    private static readonly string ChromeId = Guid.NewGuid().ToString("N");
    private static readonly string KakaoId = Guid.NewGuid().ToString("N");

    [Fact]
    public void Round_Trips_All_Line_Types()
    {
        var data = new EnforcementData { Revision = 9 };
        data.Apps.Add(new EnforcementApp { Id = ChromeId, Kind = EnforcementApp.KindWindow, Match = @"C:\Program Files\Google\Chrome\Application\chrome.exe" });
        data.Apps.Add(new EnforcementApp { Id = "pkg", Kind = EnforcementApp.KindPackage, Match = "Contoso.App_8wekyb3d8bbwe" });
        data.Apps.Add(new EnforcementApp { Id = KakaoId, Kind = EnforcementApp.KindLaunch, Match = @"C:\apps\한글.exe", LockedAtTicks = 638000000000000000 });
        data.Unlocks.Add(new EnforcementUnlock { Session = 2, Sid = "S-1-5-21-1-2-3-1001", AppId = ChromeId });
        data.Close.Add(@"C:\apps\한글.exe");

        var parsed = EnforcementData.Parse(data.Serialize());

        Assert.Equal(9, parsed.Revision);
        Assert.Equal(3, parsed.Apps.Count);
        Assert.Equal(data.Apps[2].Match, parsed.Apps[2].Match);
        Assert.Equal(638000000000000000, parsed.Apps[2].LockedAtTicks);
        Assert.Equal(EnforcementApp.KindPackage, parsed.Apps[1].Kind);
        Assert.Single(parsed.Unlocks);
        Assert.Equal(data.Close, parsed.Close);
    }

    [Fact]
    public void Relocked_Group_And_App_Names_Round_Trip()
    {
        var data = new EnforcementData { Revision = 3 };
        data.Apps.Add(new EnforcementApp { Id = ChromeId, Kind = EnforcementApp.KindWindow, Match = @"C:\c\chrome.exe", Name = "크롬" });
        data.Apps.Add(new EnforcementApp { Id = KakaoId, Kind = EnforcementApp.KindLaunch, Match = @"C:\k\k.exe", LockedAtTicks = 5 });
        data.Relocked.Add(new EnforcementUnlock { Session = 1, Sid = "S-1-5-21-1", AppId = ChromeId });
        data.Relocked.Add(new EnforcementUnlock { Session = 1, Sid = "S-1-5-21-1", AppId = KakaoId });
        data.Relocked.Add(new EnforcementUnlock { Session = 2, Sid = "S-1-5-21-1", AppId = "other" });

        var parsed = EnforcementData.Parse(data.Serialize());

        Assert.Equal("크롬", parsed.Apps[0].Name);
        Assert.Equal(string.Empty, parsed.Apps[1].Name);
        Assert.Equal(new[] { ChromeId, KakaoId }, parsed.RelockedApps(1, "s-1-5-21-1").ToArray());
        Assert.Empty(parsed.RelockedApps(3, "S-1-5-21-1"));
    }

    [Fact]
    public void Unlock_Applies_Only_To_The_Same_User_And_Session()
    {
        var data = new EnforcementData { Revision = 1 };
        data.Unlocks.Add(new EnforcementUnlock { Session = 2, Sid = "S-1-5-21-1-2-3-1001", AppId = ChromeId });
        var parsed = EnforcementData.Parse(data.Serialize());

        Assert.True(parsed.IsUnlocked(2, "s-1-5-21-1-2-3-1001", ChromeId));
        Assert.False(parsed.IsUnlocked(3, "S-1-5-21-1-2-3-1001", ChromeId));
        Assert.False(parsed.IsUnlocked(2, "S-1-5-21-1-2-3-1002", ChromeId));
        Assert.False(parsed.IsUnlocked(2, "S-1-5-21-1-2-3-1001", KakaoId));
    }

    [Theory]
    [InlineData("")]
    [InlineData("WAP-ENF 1\nrev=1\n")]
    [InlineData("WAP-ENF 2\nA:id|W|!!!|0\nrev=1\n")]
    [InlineData("WAP-ENF 2\nA:id|Z|AAAA|0\nrev=1\n")]
    [InlineData("WAP-ENF 2\nU:x|AAAA|id\nrev=1\n")]
    [InlineData("WAP-ENF 2\nG:1|2\nrev=1\n")]
    [InlineData("WAP-ENF 2\nC:AAAA\n")]
    public void Malformed_Files_Are_Rejected(string text)
    {
        Assert.Throws<FormatException>(() => EnforcementData.Parse(text));
    }
}

public sealed class AppMatcherTests
{
    [Fact]
    public void Win32_Apps_Match_By_Exact_Path_Ignoring_Case()
    {
        Assert.True(AppMatcher.Matches(false, @"C:\Apps\Chrome\chrome.exe", @"c:\apps\chrome\CHROME.exe", null));
        Assert.False(AppMatcher.Matches(false, @"C:\Apps\Chrome\chrome.exe", @"C:\Other\chrome.exe", null));
    }

    [Fact]
    public void Packaged_Apps_Match_By_Family_Not_By_Path()
    {
        Assert.True(AppMatcher.Matches(true, "Contoso.App_8wekyb3d8bbwe", @"C:\any.exe", "contoso.app_8wekyb3d8bbwe"));
        Assert.False(AppMatcher.Matches(true, "Contoso.App_8wekyb3d8bbwe", @"C:\any.exe", null));
    }

    [Fact]
    public void The_Matching_App_Is_Found_By_Kind()
    {
        var apps = new List<EnforcementApp>
        {
            new EnforcementApp { Id = "a", Kind = EnforcementApp.KindWindow, Match = @"C:\x\a.exe" },
            new EnforcementApp { Id = "b", Kind = EnforcementApp.KindPackage, Match = "Fam_1" },
        };

        Assert.Equal("a", AppMatcher.Match(apps, @"C:\x\a.exe", null)!.Id);
        Assert.Equal("b", AppMatcher.Match(apps, @"C:\y\b.exe", "Fam_1")!.Id);
        Assert.Null(AppMatcher.Match(apps, @"C:\x\other.exe", null));
    }
}

public sealed class UnlockTableTests
{
    private const string Sid = "S-1-5-21-1-2-3-1001";
    private static readonly DateTime T0 = new DateTime(2026, 11, 24, 3, 0, 0, DateTimeKind.Utc);

    private static (PolicyDocument policy, SecretsDocument secrets, AppPolicy chrome, AppPolicy kakao) Setup(int minutes = 0, bool relockOnExit = false)
    {
        var policy = new PolicyDocument();
        var chrome = new AppPolicy { Id = "chrome", Name = "Chrome", Path = @"C:\Chrome\chrome.exe", ExecutableName = "chrome.exe" };
        var kakao = new AppPolicy { Id = "kakao", Name = "Kakao", Path = @"C:\Kakao\KakaoTalk.exe", ExecutableName = "KakaoTalk.exe" };
        chrome.Launch.AllowedMinutes = kakao.Launch.AllowedMinutes = minutes;
        chrome.Launch.RelockOnExit = kakao.Launch.RelockOnExit = relockOnExit;
        policy.Apps.Add(chrome);
        policy.Apps.Add(kakao);
        var secrets = new SecretsDocument { AppPin = PinHash.Create("1234") };
        secrets.AppPin.Version = 1;
        return (policy, secrets, chrome, kakao);
    }

    private static AuthResult Auth(UnlockTable table, PolicyDocument policy, SecretsDocument secrets, AppPolicy app, string pin, DateTime now, int session = 1)
    {
        return table.Authorize(policy, secrets, app, Sid, session, pin, now, out _);
    }

    private static Dictionary<string, int> Running(params string[] keys)
    {
        var result = new Dictionary<string, int>();
        foreach (string key in keys) result[key] = 1;
        return result;
    }

    [Fact]
    public void Wrong_Pin_Is_Denied_And_Right_Pin_Unlocks_The_App_For_Every_Process()
    {
        var (policy, secrets, chrome, _) = Setup();
        var table = new UnlockTable();

        Assert.Equal(AuthResult.Prompt, Auth(table, policy, secrets, chrome, "", T0));
        Assert.Equal(AuthResult.Denied, Auth(table, policy, secrets, chrome, "0000", T0));
        Assert.False(table.IsUnlocked(Sid, 1, "chrome", T0));

        Assert.Equal(AuthResult.Approved, Auth(table, policy, secrets, chrome, "1234", T0));
        Assert.True(table.IsUnlocked(Sid, 1, "chrome", T0));
        // A second Gate for the same app is approved without a PIN.
        Assert.Equal(AuthResult.Approved, Auth(table, policy, secrets, chrome, "", T0.AddSeconds(1)));
    }

    [Fact]
    public void Unlocking_One_App_Leaves_Other_Apps_And_Sessions_Locked()
    {
        var (policy, secrets, chrome, kakao) = Setup();
        var table = new UnlockTable();

        Auth(table, policy, secrets, chrome, "1234", T0, session: 1);

        Assert.True(table.IsUnlocked(Sid, 1, "chrome", T0));
        Assert.False(table.IsUnlocked(Sid, 1, "kakao", T0));
        Assert.False(table.IsUnlocked(Sid, 2, "chrome", T0));
        Assert.False(table.IsUnlocked("S-1-5-21-1-2-3-1002", 1, "chrome", T0));
        Assert.Equal(AuthResult.Prompt, Auth(table, policy, secrets, kakao, "", T0));
    }

    [Fact]
    public void Unlock_Ends_Three_Seconds_After_The_Last_Process_Exits()
    {
        var (policy, secrets, chrome, _) = Setup();
        var table = new UnlockTable();
        Auth(table, policy, secrets, chrome, "1234", T0);

        Assert.False(table.Observe(Running("1|chrome"), T0.AddSeconds(1)));
        // The launcher hands off to a running copy and exits: a short gap must not relock.
        Assert.False(table.Observe(Running(), T0.AddSeconds(2)));
        Assert.True(table.IsUnlocked(Sid, 1, "chrome", T0.AddSeconds(2)));
        Assert.False(table.Observe(Running("1|chrome"), T0.AddSeconds(3)));
        Assert.False(table.Observe(Running(), T0.AddSeconds(4)));
        Assert.True(table.Observe(Running(), T0.AddSeconds(7)));
        Assert.False(table.IsUnlocked(Sid, 1, "chrome", T0.AddSeconds(7)));
    }

    [Fact]
    public void Unlock_Ends_After_Thirty_Seconds_Without_The_App_Starting()
    {
        var (policy, secrets, chrome, _) = Setup();
        var table = new UnlockTable();
        Auth(table, policy, secrets, chrome, "1234", T0);

        Assert.False(table.Observe(Running(), T0.AddSeconds(29)));
        Assert.True(table.Observe(Running(), T0.AddSeconds(30)));
        Assert.False(table.IsUnlocked(Sid, 1, "chrome", T0.AddSeconds(30)));
    }

    [Fact]
    public void Allowed_Minutes_Without_Relock_On_Exit_Survives_Closing_The_App_Until_Time_Is_Up()
    {
        var (policy, secrets, chrome, _) = Setup(minutes: 1, relockOnExit: false);
        var table = new UnlockTable();
        Auth(table, policy, secrets, chrome, "1234", T0);
        table.Observe(Running("1|chrome"), T0.AddSeconds(1));

        Assert.False(table.Observe(Running(), T0.AddSeconds(20)));
        Assert.True(table.IsUnlocked(Sid, 1, "chrome", T0.AddSeconds(20)));
        Assert.Equal(AuthResult.Approved, Auth(table, policy, secrets, chrome, "", T0.AddSeconds(20)));

        Assert.True(table.Observe(Running("1|chrome"), T0.AddSeconds(61)));
        Assert.False(table.IsUnlocked(Sid, 1, "chrome", T0.AddSeconds(61)));
    }

    [Fact]
    public void Allowed_Minutes_With_Relock_On_Exit_Still_Ends_When_The_App_Closes()
    {
        var (policy, secrets, chrome, _) = Setup(minutes: 10, relockOnExit: true);
        var table = new UnlockTable();
        Auth(table, policy, secrets, chrome, "1234", T0);
        table.Observe(Running("1|chrome"), T0.AddSeconds(1));

        Assert.True(table.Observe(Running(), T0.AddSeconds(5)));
    }

    [Fact]
    public void Changing_The_Pin_Or_Unlocking_The_App_Ends_The_Unlock()
    {
        var (policy, secrets, chrome, _) = Setup();
        var table = new UnlockTable();
        Auth(table, policy, secrets, chrome, "1234", T0);

        Assert.False(table.Prune(policy, secrets));

        secrets.AppPin.Version = 2;
        Assert.True(table.Prune(policy, secrets));
        Assert.False(table.IsUnlocked(Sid, 1, "chrome", T0));

        secrets.AppPin.Version = 1;
        Auth(table, policy, secrets, chrome, "1234", T0);
        chrome.Locked = false;
        Assert.True(table.Prune(policy, secrets));
    }

    [Fact]
    public void Revoking_A_Session_Keeps_Other_Sessions()
    {
        var (policy, secrets, chrome, _) = Setup();
        var table = new UnlockTable();
        Auth(table, policy, secrets, chrome, "1234", T0, session: 1);
        Auth(table, policy, secrets, chrome, "1234", T0, session: 2);

        Assert.True(table.RevokeSession(1));

        Assert.False(table.IsUnlocked(Sid, 1, "chrome", T0));
        Assert.True(table.IsUnlocked(Sid, 2, "chrome", T0));
        Assert.Equal(2, table.Snapshot(T0).Single().Session);
    }

    [Fact]
    public void Five_Wrong_Pins_Rate_Limit_Every_Prompt()
    {
        var (policy, secrets, chrome, kakao) = Setup();
        var table = new UnlockTable();
        AuthResult last = AuthResult.Denied;
        for (int i = 0; i < 5; i++) last = Auth(table, policy, secrets, chrome, "0000", T0);

        Assert.Equal(AuthResult.RateLimited, last);
        Assert.Equal(AuthResult.RateLimited, Auth(table, policy, secrets, kakao, "1234", T0.AddSeconds(5)));
        Assert.Equal(AuthResult.Approved, Auth(table, policy, secrets, kakao, "1234", T0.AddSeconds(31)));
    }

    private static (PolicyDocument policy, SecretsDocument secrets, UnlockTable table, AppPolicy chrome, AppPolicy kakao) RelockedPair(DateTime now)
    {
        var (policy, secrets, chrome, kakao) = Setup();
        var table = new UnlockTable();
        Auth(table, policy, secrets, chrome, "1234", now);
        Auth(table, policy, secrets, kakao, "1234", now);
        table.Observe(Running("1|chrome", "1|kakao"), now.AddSeconds(1));
        return (policy, secrets, table, chrome, kakao);
    }

    [Fact]
    public void Apps_Running_At_Screen_Lock_Become_One_Relocked_Group()
    {
        var (_, _, table, _, _) = RelockedPair(T0);

        table.RevokeAll();

        Assert.Equal(new[] { "chrome", "kakao" }, table.RelockedSnapshot().Select(r => r.AppId).ToArray());
        Assert.False(table.IsUnlocked(Sid, 1, "chrome", T0));
    }

    [Fact]
    public void One_Pin_Reopens_The_Whole_Relocked_Group()
    {
        var (policy, secrets, table, chrome, _) = RelockedPair(T0);
        table.RevokeAll();

        var result = table.Authorize(policy, secrets, chrome, Sid, 1, "1234", T0.AddSeconds(10), new[] { "kakao" }, out _);

        Assert.Equal(AuthResult.Approved, result);
        Assert.True(table.IsUnlocked(Sid, 1, "chrome", T0.AddSeconds(10)));
        Assert.True(table.IsUnlocked(Sid, 1, "kakao", T0.AddSeconds(10)));
        Assert.Empty(table.RelockedSnapshot());
    }

    [Fact]
    public void A_Wrong_Pin_Unlocks_Nothing_And_Counts_One_Failure()
    {
        var (policy, secrets, table, chrome, _) = RelockedPair(T0);
        table.RevokeAll();

        var result = table.Authorize(policy, secrets, chrome, Sid, 1, "0000", T0.AddSeconds(10), new[] { "kakao" }, out _);

        Assert.Equal(AuthResult.Denied, result);
        Assert.False(table.IsUnlocked(Sid, 1, "kakao", T0.AddSeconds(10)));
    }

    [Fact]
    public void Only_Relocked_Apps_Can_Ride_Along_And_An_Own_Pin_Is_Respected()
    {
        var (policy, secrets, chrome, kakao) = Setup();
        var table = new UnlockTable();
        Auth(table, policy, secrets, chrome, "1234", T0);
        table.Observe(Running("1|chrome"), T0.AddSeconds(1));
        table.RevokeAll();
        secrets.SetAppPin("kakao", PinHash.Create("9999"));

        // kakao was never unlocked here, so it is not part of the group even when named in the request.
        table.Authorize(policy, secrets, chrome, Sid, 1, "1234", T0.AddSeconds(10), new[] { "kakao" }, out _);

        Assert.True(table.IsUnlocked(Sid, 1, "chrome", T0.AddSeconds(10)));
        Assert.False(table.IsUnlocked(Sid, 1, "kakao", T0.AddSeconds(10)));
    }

    [Fact]
    public void A_Relocked_App_Leaves_The_Group_When_It_Is_No_Longer_Running()
    {
        var (_, _, table, _, _) = RelockedPair(T0);
        table.RevokeAll();

        Assert.False(table.Observe(Running("1|chrome", "1|kakao"), T0.AddSeconds(3)));
        Assert.True(table.Observe(Running("1|kakao"), T0.AddSeconds(9)));

        Assert.Equal(new[] { "kakao" }, table.RelockedSnapshot().Select(r => r.AppId).ToArray());
    }

    [Fact]
    public void Unlock_All_Followed_By_Lock_All_Offers_The_Running_Apps_As_A_Group()
    {
        var (policy, secrets, table, chrome, kakao) = RelockedPair(T0);

        chrome.Locked = false;
        kakao.Locked = false;
        Assert.True(table.Prune(policy, secrets));

        Assert.Equal(2, table.RelockedSnapshot().Count);
    }

    [Fact]
    public void Apps_Open_When_Locked_Join_The_Group_Without_Any_Earlier_Pin_Unlock()
    {
        var (policy, secrets, chrome, kakao) = Setup();
        var table = new UnlockTable();

        Assert.True(table.AddRelockedRunning(chrome, Sid, 1, T0));
        Assert.True(table.AddRelockedRunning(kakao, Sid, 1, T0));
        Assert.False(table.AddRelockedRunning(kakao, Sid, 1, T0));

        var result = table.Authorize(policy, secrets, chrome, Sid, 1, "1234", T0, new[] { "kakao" }, out _);

        Assert.Equal(AuthResult.Approved, result);
        Assert.True(table.IsUnlocked(Sid, 1, "kakao", T0));
        Assert.Empty(table.RelockedSnapshot());
    }

    [Fact]
    public void An_Unlocked_App_Appears_In_The_Enforcement_Snapshot_Until_It_Ends()
    {
        var (policy, secrets, chrome, _) = Setup();
        var table = new UnlockTable();
        Auth(table, policy, secrets, chrome, "1234", T0);

        var unlock = Assert.Single(table.Snapshot(T0));
        Assert.Equal("chrome", unlock.AppId);
        Assert.Equal(1, table.CountSessions("chrome"));
    }
}
