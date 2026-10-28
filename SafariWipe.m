#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <WebKit/WebKit.h>
#import <Security/Security.h>
#import <QuartzCore/QuartzCore.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreTelephony/CTCarrier.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <notify.h>
#import <spawn.h>
#import <signal.h>
#import <unistd.h>
#import <stdlib.h>
#import <sys/wait.h>

extern char **environ;

static NSHashTable<WKWebView *> *gTrackedWebViews = nil;

static void TrackWebView(WKWebView *wv) {
    if (!wv) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gTrackedWebViews) {
            gTrackedWebViews = [NSHashTable weakObjectsHashTable];
        }
        [gTrackedWebViews addObject:wv];
    });
}

static void FindWebViewsInView(UIView *view, NSMutableSet<WKWebView *> *outSet) {
    if (!view || !outSet) return;
    if ([view isKindOfClass:[WKWebView class]]) {
        [outSet addObject:(WKWebView *)view];
    }
    for (UIView *sub in view.subviews) {
        FindWebViewsInView(sub, outSet);
    }
}

static NSSet<WKWebView *> *GetAllActiveSafariWebViews(void) {
    NSMutableSet<WKWebView *> *all = [NSMutableSet set];
    if (gTrackedWebViews) {
        for (WKWebView *wv in gTrackedWebViews) {
            if (wv) [all addObject:wv];
        }
    }
    UIApplication *app = [UIApplication sharedApplication];
    for (UIScene *scene in app.connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]]) {
            UIWindowScene *ws = (UIWindowScene *)scene;
            for (UIWindow *win in ws.windows) {
                FindWebViewsInView(win, all);
            }
        }
    }
    return all;
}

static void RunCommandAndWait(const char *binCandidates[], char *const argv[]) {
    const char *binPath = NULL;
    for (int i = 0; binCandidates[i] != NULL; i++) {
        if (access(binCandidates[i], X_OK) == 0) {
            binPath = binCandidates[i];
            break;
        }
    }
    if (!binPath) return;
    pid_t pid = 0;
    if (posix_spawn(&pid, binPath, NULL, NULL, argv, environ) == 0 && pid > 0) {
        int status = 0;
        waitpid(pid, &status, 0);
    }
}

static void KillBackgroundWebKitDaemons(void) {
    const char *killallPaths[] = {
        "/var/jb/usr/bin/killall",
        "/usr/bin/killall",
        NULL
    };
    const char *binPath = NULL;
    for (int i = 0; killallPaths[i] != NULL; i++) {
        if (access(killallPaths[i], X_OK) == 0) {
            binPath = killallPaths[i];
            break;
        }
    }
    if (binPath) {
        pid_t pid = 0;
        char *argv[] = {
            (char *)"killall",
            (char *)"-9",
            (char *)"com.apple.WebKit.Networking",
            (char *)"com.apple.WebKit.WebContent",
            (char *)"com.apple.WebKit.GPU",
            (char *)"SafariViewService",
            (char *)"webbookmarksd",
            (char *)"swcd",
            NULL
        };
        posix_spawn(&pid, binPath, NULL, NULL, argv, environ);
    }
}

@interface SWSpoofManager : NSObject
@property (nonatomic, copy) NSString *userAgent;
@property (nonatomic, copy) NSString *iosVersion;
@property (nonatomic, copy) NSString *idfv;
@property (nonatomic, copy) NSString *idfa;
@property (nonatomic, copy) NSString *serial;
@property (nonatomic, copy) NSString *installId;
@property (nonatomic, copy) NSString *localeCode;
@property (nonatomic, copy) NSString *timeZoneName;
@property (nonatomic, copy) NSString *carrierName;
@property (nonatomic, copy) NSString *carrierISO;
@property (nonatomic, copy) NSString *carrierMCC;
@property (nonatomic, copy) NSString *carrierMNC;
@property (nonatomic, assign) NSInteger cpuCores;
@property (nonatomic, assign) NSInteger canvasSeed;
@property (nonatomic, assign) BOOL isButtonVisible;
@property (nonatomic, assign) BOOL forceAppBanner;
@property (nonatomic, copy) NSString *pendingRestoreWebStorageJSON;
@property (nonatomic, copy) NSString *pendingRestoreURL;

+ (instancetype)shared;
- (NSString *)profilePath;
- (void)loadOrGenerateProfile;
- (void)rotateProfile;
- (void)saveProfile;
- (NSString *)buildEnvironmentJS;
- (void)injectIntoUserContentController:(WKUserContentController *)ucc;
@end

@implementation SWSpoofManager

+ (instancetype)shared {
    static SWSpoofManager *inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        inst = [[self alloc] init];
        [inst loadOrGenerateProfile];
    });
    return inst;
}

- (NSString *)profilePath {
    NSString *docDir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:docDir withIntermediateDirectories:YES attributes:nil error:nil];
    return [docDir stringByAppendingPathComponent:@".safari_amzfr_v70.plist"];
}

- (NSString *)randomStringWithChars:(NSString *)chars length:(NSUInteger)len {
    NSMutableString *s = [NSMutableString stringWithCapacity:len];
    for (NSUInteger i = 0; i < len; i++) {
        uint32_t idx = arc4random_uniform((uint32_t)chars.length);
        [s appendFormat:@"%C", [chars characterAtIndex:idx]];
    }
    return s;
}

- (void)loadOrGenerateProfile {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:[self profilePath]];
    NSString *savedVer = dict[@"iosVersion"] ?: @"";
    BOOL isValid16_6Plus = ([savedVer hasPrefix:@"16.6"] || [savedVer hasPrefix:@"16.7"]);

    if (dict && dict[@"userAgent"] && dict[@"idfv"] && isValid16_6Plus) {
        self.userAgent = dict[@"userAgent"];
        self.iosVersion = savedVer;
        self.idfv = dict[@"idfv"];
        self.idfa = dict[@"idfa"] ?: [[NSUUID UUID] UUIDString];
        self.serial = dict[@"serial"] ?: [self randomStringWithChars:@"ABCDEFGHJKLMNPQRSTUVWXYZ0123456789" length:12];
        self.installId = dict[@"installId"] ?: [[NSUUID UUID] UUIDString];
        self.localeCode = dict[@"localeCode"] ?: @"fr_FR";
        self.timeZoneName = dict[@"timeZoneName"] ?: @"Europe/Paris";
        self.carrierName = dict[@"carrierName"] ?: @"Orange F";
        self.carrierISO = dict[@"carrierISO"] ?: @"fr";
        self.carrierMCC = dict[@"carrierMCC"] ?: @"208";
        self.carrierMNC = dict[@"carrierMNC"] ?: @"01";
        self.cpuCores = [dict[@"cpuCores"] integerValue] ?: 6;
        self.canvasSeed = [dict[@"canvasSeed"] integerValue] ?: 582913;
        self.isButtonVisible = dict[@"isButtonVisible"] ? [dict[@"isButtonVisible"] boolValue] : YES;
        self.forceAppBanner = dict[@"forceAppBanner"] ? [dict[@"forceAppBanner"] boolValue] : YES;
        self.pendingRestoreWebStorageJSON = dict[@"pendingRestoreWebStorageJSON"];
        self.pendingRestoreURL = dict[@"pendingRestoreURL"];
    } else {
        self.isButtonVisible = dict[@"isButtonVisible"] ? [dict[@"isButtonVisible"] boolValue] : YES;
        self.forceAppBanner = dict[@"forceAppBanner"] ? [dict[@"forceAppBanner"] boolValue] : YES;
        [self rotateProfile];
    }
}

- (void)saveProfile {
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithDictionary:@{
        @"userAgent": self.userAgent ?: @"",
        @"iosVersion": self.iosVersion ?: @"16.6",
        @"idfv": self.idfv ?: [[NSUUID UUID] UUIDString],
        @"idfa": self.idfa ?: [[NSUUID UUID] UUIDString],
        @"serial": self.serial ?: @"",
        @"installId": self.installId ?: @"",
        @"localeCode": self.localeCode ?: @"fr_FR",
        @"timeZoneName": self.timeZoneName ?: @"Europe/Paris",
        @"carrierName": self.carrierName ?: @"Orange F",
        @"carrierISO": self.carrierISO ?: @"fr",
        @"carrierMCC": self.carrierMCC ?: @"208",
        @"carrierMNC": self.carrierMNC ?: @"01",
        @"cpuCores": @(self.cpuCores),
        @"canvasSeed": @(self.canvasSeed),
        @"isButtonVisible": @(self.isButtonVisible),
        @"forceAppBanner": @(self.forceAppBanner)
    }];
    if (self.pendingRestoreWebStorageJSON) dict[@"pendingRestoreWebStorageJSON"] = self.pendingRestoreWebStorageJSON;
    if (self.pendingRestoreURL) dict[@"pendingRestoreURL"] = self.pendingRestoreURL;
    [dict writeToFile:[self profilePath] atomically:YES];
}

- (void)rotateProfile {
    NSArray<NSArray<NSString *> *> *ios16_6PlusProfiles = @[
        @[@"16_6",    @"16.6", @"16.6"],
        @[@"16_6_1",  @"16.6", @"16.6.1"],
        @[@"16_7",    @"16.6", @"16.7"],
        @[@"16_7_1",  @"16.6", @"16.7.1"],
        @[@"16_7_2",  @"16.6", @"16.7.2"],
        @[@"16_7_4",  @"16.6", @"16.7.4"],
        @[@"16_7_5",  @"16.6", @"16.7.5"],
        @[@"16_7_7",  @"16.6", @"16.7.7"],
        @[@"16_7_8",  @"16.6", @"16.7.8"],
        @[@"16_7_10", @"16.6", @"16.7.10"],
        @[@"16_7_16", @"16.6", @"16.7.16"]
    ];

    NSArray<NSString *> *picked = ios16_6PlusProfiles[arc4random_uniform((uint32_t)ios16_6PlusProfiles.count)];

    NSArray<NSArray<NSString *> *> *frCarriers = @[
        @[@"Orange F",         @"fr", @"208", @"01"],
        @[@"SFR",              @"fr", @"208", @"10"],
        @[@"Bouygues Telecom", @"fr", @"208", @"20"],
        @[@"Free",             @"fr", @"208", @"15"]
    ];
    NSArray<NSString *> *cPicked = frCarriers[arc4random_uniform((uint32_t)frCarriers.count)];

    self.iosVersion = picked[2];
    self.userAgent = [NSString stringWithFormat:@"Mozilla/5.0 (iPhone; CPU iPhone OS %@ like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/%@ Mobile/15E148 Safari/604.1", picked[0], picked[1]];
    self.idfv = [[NSUUID UUID] UUIDString];
    self.idfa = [[NSUUID UUID] UUIDString];
    self.serial = [self randomStringWithChars:@"ABCDEFGHJKLMNPQRSTUVWXYZ0123456789" length:12];
    self.installId = [[NSUUID UUID] UUIDString];
    self.localeCode = @"fr_FR";
    self.timeZoneName = @"Europe/Paris";
    self.carrierName = cPicked[0];
    self.carrierISO = cPicked[1];
    self.carrierMCC = cPicked[2];
    self.carrierMNC = cPicked[3];
    self.cpuCores = (arc4random_uniform(2) == 0) ? 6 : 4;

    NSInteger newSeed = (NSInteger)(arc4random_uniform(899999) + 100000);
    if (newSeed == self.canvasSeed) newSeed += 7;
    self.canvasSeed = newSeed;
    self.pendingRestoreWebStorageJSON = nil;
    self.pendingRestoreURL = nil;

    [self saveProfile];
}

- (NSString *)buildEnvironmentJS {
    NSTimeZone *parisTZ = [NSTimeZone timeZoneWithName:@"Europe/Paris"];
    NSInteger secondsFromGMT = [parisTZ secondsFromGMTForDate:[NSDate date]];
    NSInteger jsTzOffset = -(secondsFromGMT / 60);
    NSInteger showBannerFlag = self.forceAppBanner ? 1 : 0;

    return [NSString stringWithFormat:
        @"(function() {"
        @"  try {"
        @"    const seed = %ld;"
        @"    const cores = %ld;"
        @"    const tzOffset = %ld;"
        @"    const forceBanner = %ld;"
        @"    const deltaR = (seed %% 5) + 1;"
        @"    const deltaG = ((seed >> 3) %% 5) + 1;"
        @"    const deltaB = ((seed >> 6) %% 5) + 1;"
        @"    const nativeToString = Function.prototype.toString;"
        @"    const maskedFns = new WeakMap();"
        @"    const noisedBuffers = new WeakSet();"
        @"    const toStrProxy = new Proxy(nativeToString, {"
        @"      apply(target, thisArg, args) {"
        @"        if (maskedFns.has(thisArg)) return maskedFns.get(thisArg);"
        @"        return Reflect.apply(target, thisArg, args);"
        @"      }"
        @"    });"
        @"    maskedFns.set(toStrProxy, 'function toString() { [native code] }');"
        @"    Function.prototype.toString = toStrProxy;"
        @"    function maskGetter(proto, prop, valFn) {"
        @"      if (!proto) return;"
        @"      const desc = Object.getOwnPropertyDescriptor(proto, prop);"
        @"      if (!desc) return;"
        @"      const getter = new Proxy(desc.get || function(){}, {"
        @"        apply() { return valFn(); }"
        @"      });"
        @"      maskedFns.set(getter, 'function get ' + prop + '() { [native code] }');"
        @"      Object.defineProperty(proto, prop, { get: getter, enumerable: desc.enumerable, configurable: desc.configurable });"
        @"    }"
        @"    function maskMethod(proto, name, applyFn) {"
        @"      if (!proto) return;"
        @"      const orig = proto[name];"
        @"      if (typeof orig !== 'function') return;"
        @"      const proxied = new Proxy(orig, { apply: applyFn });"
        @"      maskedFns.set(proxied, 'function ' + name + '() { [native code] }');"
        @"      proto[name] = proxied;"
        @"    }"
        @"    maskGetter(Navigator.prototype, 'language', () => 'fr-FR');"
        @"    maskGetter(Navigator.prototype, 'languages', () => ['fr-FR', 'fr']);"
        @"    maskGetter(Navigator.prototype, 'hardwareConcurrency', () => cores);"
        @"    maskMethod(Date.prototype, 'getTimezoneOffset', () => tzOffset);"
        @"    maskMethod(Intl.DateTimeFormat.prototype, 'resolvedOptions', (target, thisArg, args) => {"
        @"      const res = Reflect.apply(target, thisArg, args);"
        @"      res.timeZone = 'Europe/Paris';"
        @"      if (!res.locale || res.locale.indexOf('fr') !== 0) res.locale = 'fr-FR';"
        @"      return res;"
        @"    });"
        @"    const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;"
        @"    const origPutImageData = CanvasRenderingContext2D.prototype.putImageData;"
        @"    function applyPixelNoise(data) {"
        @"      if (!data || data.length < 64) return;"
        @"      let changed = 0;"
        @"      const start = ((seed %% 13) * 4);"
        @"      for (let i = start; i < data.length - 4; i += 36) {"
        @"        if (data[i + 3] > 32) {"
        @"          data[i]     = (data[i] > 245)     ? (data[i] - deltaR)     : (data[i] + deltaR);"
        @"          data[i + 1] = (data[i + 1] > 245) ? (data[i + 1] - deltaG) : (data[i + 1] + deltaG);"
        @"          data[i + 2] = (data[i + 2] > 245) ? (data[i + 2] - deltaB) : (data[i + 2] + deltaB);"
        @"          changed++;"
        @"          if (changed >= 12) break;"
        @"        }"
        @"      }"
        @"      if (changed === 0) {"
        @"        const mid = Math.floor(data.length / 8) * 4;"
        @"        data[mid]     = (data[mid] + deltaR) & 255;"
        @"        data[mid + 1] = (data[mid + 1] + deltaG) & 255;"
        @"        data[mid + 3] = (data[mid + 3] === 0) ? deltaB : data[mid + 3];"
        @"      }"
        @"    }"
        @"    maskMethod(CanvasRenderingContext2D.prototype, 'getImageData', (target, thisArg, args) => {"
        @"      const img = Reflect.apply(target, thisArg, args);"
        @"      try { applyPixelNoise(img.data); } catch(e) {}"
        @"      return img;"
        @"    });"
        @"    function injectCanvas2DNoise(canvas) {"
        @"      try {"
        @"        const ctx2d = canvas.getContext('2d');"
        @"        if (ctx2d && canvas.width >= 2 && canvas.height >= 2) {"
        @"          const w = Math.min(canvas.width, 64);"
        @"          const h = Math.min(canvas.height, 32);"
        @"          const img = Reflect.apply(origGetImageData, ctx2d, [0, 0, w, h]);"
        @"          applyPixelNoise(img.data);"
        @"          Reflect.apply(origPutImageData, ctx2d, [img, 0, 0]);"
        @"        }"
        @"      } catch(e) {}"
        @"    }"
        @"    maskMethod(HTMLCanvasElement.prototype, 'toDataURL', (target, thisArg, args) => {"
        @"      injectCanvas2DNoise(thisArg);"
        @"      return Reflect.apply(target, thisArg, args);"
        @"    });"
        @"    maskMethod(HTMLCanvasElement.prototype, 'toBlob', (target, thisArg, args) => {"
        @"      injectCanvas2DNoise(thisArg);"
        @"      return Reflect.apply(target, thisArg, args);"
        @"    });"
        @"    function noiseWebGLPixels(target, thisArg, args) {"
        @"      const res = Reflect.apply(target, thisArg, args);"
        @"      try {"
        @"        const pixels = args[6];"
        @"        if (pixels && pixels.length >= 64) {"
        @"          applyPixelNoise(pixels);"
        @"        }"
        @"      } catch(e) {}"
        @"      return res;"
        @"    }"
        @"    if (typeof WebGLRenderingContext !== 'undefined') {"
        @"      maskMethod(WebGLRenderingContext.prototype, 'readPixels', noiseWebGLPixels);"
        @"    }"
        @"    if (typeof WebGL2RenderingContext !== 'undefined') {"
        @"      maskMethod(WebGL2RenderingContext.prototype, 'readPixels', noiseWebGLPixels);"
        @"    }"
        @"    if (typeof AudioBuffer !== 'undefined') {"
        @"      maskMethod(AudioBuffer.prototype, 'getChannelData', (target, thisArg, args) => {"
        @"        const ch = Reflect.apply(target, thisArg, args);"
        @"        try {"
        @"          if (ch && ch.length > 10 && !noisedBuffers.has(ch)) {"
        @"            noisedBuffers.add(ch);"
        @"            const offset = ((seed %% 9) + 1) * 1e-7;"
        @"            for (let i = 0; i < ch.length; i += 64) { ch[i] += offset; }"
        @"          }"
        @"        } catch(e) {}"
        @"        return ch;"
        @"      });"
        @"    }"
        @"    const rectJitter = ((seed %% 11) + 1) * 1e-6;"
        @"    maskMethod(Element.prototype, 'getBoundingClientRect', (target, thisArg, args) => {"
        @"      const rect = Reflect.apply(target, thisArg, args);"
        @"      try {"
        @"        if (rect && rect.width > 0 && rect.height > 0) {"
        @"          return new DOMRect(rect.x + rectJitter, rect.y, rect.width + rectJitter, rect.height);"
        @"        }"
        @"      } catch(e) {}"
        @"      return rect;"
        @"    });"
        @"    if (forceBanner === 1 && window === window.top) {"
        @"      window.addEventListener('load', function() {"
        @"        try {"
        @"          if (location.hostname.indexOf('amazon.') === -1) return;"
        @"          localStorage.removeItem('amz-smart-banner-dismissed');"
        @"          if (!document.querySelector('meta[name=\"apple-itunes-app\"]')) {"
        @"            const m = document.createElement('meta');"
        @"            m.name = 'apple-itunes-app';"
        @"            m.content = 'app-id=297606951';"
        @"            if (document.head) document.head.appendChild(m);"
        @"          }"
        @"          if (!document.getElementById('nav-smart-app-banner-af')) {"
        @"            const bar = document.createElement('div');"
        @"            bar.id = 'nav-smart-app-banner-af';"
        @"            bar.style.cssText = 'display:flex;align-items:center;justify-content:space-between;background:#f3f4f6;padding:8px 12px;border-bottom:1px solid #d5d9d9;font-family:-apple-system,BlinkMacSystemFont,sans-serif;height:56px;box-sizing:border-box;width:100%%;z-index:9999;';"
        @"            bar.innerHTML = '<div style=\"display:flex;align-items:center;gap:10px;\"><span style=\"color:#555;font-size:16px;padding-right:2px;\">&times;</span><div style=\"width:38px;height:38px;border-radius:8px;background:#d9b382;display:flex;align-items:center;justify-content:center;font-weight:bold;color:#111;font-size:18px;box-shadow:0 1px 2px rgba(0,0,0,0.15);\">a</div><div style=\"line-height:1.25;\"><div style=\"font-weight:700;font-size:14px;color:#0f1111;\">Fast. Easy.</div><div style=\"font-size:12px;color:#333;\">Shop in our free App today</div></div></div><div style=\"border:1px solid #c7c7c7;background:#fff;border-radius:16px;padding:5px 18px;color:#0066ff;font-weight:700;font-size:14px;\">Open</div>';"
        @"            if (document.body && document.body.firstChild) {"
        @"              document.body.insertBefore(bar, document.body.firstChild);"
        @"            }"
        @"          }"
        @"        } catch(e) {}"
        @"      });"
        @"    }"
        @"  } catch (err) {}"
        @"})();",
        (long)self.canvasSeed, (long)self.cpuCores, (long)jsTzOffset, (long)showBannerFlag];
}

- (void)injectIntoUserContentController:(WKUserContentController *)ucc {
    if (!ucc) return;
    for (WKUserScript *existing in ucc.userScripts) {
        if ([existing.source containsString:@"Europe/Paris"]) {
            return;
        }
    }
    NSString *jsCode = [self buildEnvironmentJS];
    WKUserScript *envScript = [[WKUserScript alloc] initWithSource:jsCode
                                                     injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                                  forMainFrameOnly:NO];
    [ucc addUserScript:envScript];
}

@end

// ============================================================================
// THU THẬP COOKIE ĐA TẦNG (TRẢ VỀ CẢ ĐỐI TƯỢNG NSHTTPCookie ĐẦY ĐỦ THUỘC TÍNH)
// ============================================================================
static void CollectAllSafariCookiesDetailed(void (^completion)(NSArray<NSString *> *amzPairs, NSArray<NSString *> *allPairs, NSArray<NSDictionary *> *cookieDicts)) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSMutableDictionary<NSString *, NSString *> *amzMap = [NSMutableDictionary dictionary];
        NSMutableDictionary<NSString *, NSString *> *allMap = [NSMutableDictionary dictionary];
        NSMutableDictionary<NSString *, NSDictionary *> *rawPropMap = [NSMutableDictionary dictionary];

        void (^addCookieObj)(NSHTTPCookie *) = ^(NSHTTPCookie *c) {
            if (!c || !c.name || !c.value) return;
            NSString *pair = [NSString stringWithFormat:@"%@=%@", c.name, c.value];
            allMap[c.name] = pair;

            NSMutableDictionary *props = [NSMutableDictionary dictionary];
            props[NSHTTPCookieName] = c.name;
            props[NSHTTPCookieValue] = c.value;
            props[NSHTTPCookieDomain] = c.domain ?: @".amazon.fr";
            props[NSHTTPCookiePath] = c.path ?: @"/";
            if (c.expiresDate) {
                props[NSHTTPCookieExpires] = c.expiresDate;
            } else {
                props[NSHTTPCookieExpires] = [NSDate dateWithTimeIntervalSinceNow:86400 * 365];
            }
            if (c.isSecure) props[NSHTTPCookieSecure] = @"TRUE";

            NSString *uniqueKey = [NSString stringWithFormat:@"%@|%@|%@", c.domain ?: @"", c.path ?: @"/", c.name];
            rawPropMap[uniqueKey] = props;

            NSString *dom = (c.domain ?: @"").lowercaseString;
            NSString *nam = c.name.lowercaseString;
            if ([dom containsString:@"amazon"] ||
                [nam hasSuffix:@"acbfr"] ||
                [nam isEqualToString:@"session-id"] ||
                [nam isEqualToString:@"session-token"] ||
                [nam isEqualToString:@"session-id-time"] ||
                [nam isEqualToString:@"i18n-prefs"] ||
                [nam isEqualToString:@"sp-cdn"]) {
                amzMap[c.name] = pair;
            }
        };

        for (NSHTTPCookie *c in [[NSHTTPCookieStorage sharedHTTPCookieStorage] cookies]) {
            addCookieObj(c);
        }

        NSSet<WKWebView *> *webViews = GetAllActiveSafariWebViews();
        NSMutableSet<WKWebsiteDataStore *> *dataStores = [NSMutableSet set];
        if ([WKWebsiteDataStore defaultDataStore]) {
            [dataStores addObject:[WKWebsiteDataStore defaultDataStore]];
        }
        for (WKWebView *wv in webViews) {
            if (wv.configuration.websiteDataStore) {
                [dataStores addObject:wv.configuration.websiteDataStore];
            }
        }

        dispatch_group_t grp = dispatch_group_create();

        for (WKWebsiteDataStore *ds in dataStores) {
            dispatch_group_enter(grp);
            [ds.httpCookieStore getAllCookies:^(NSArray<NSHTTPCookie *> *cookies) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    for (NSHTTPCookie *c in cookies) {
                        addCookieObj(c);
                    }
                    dispatch_group_leave(grp);
                });
            }];
        }

        for (WKWebView *wv in webViews) {
            dispatch_group_enter(grp);
            NSString *currentHost = (wv.URL.host ?: @".amazon.fr").lowercaseString;
            [wv evaluateJavaScript:@"document.cookie" completionHandler:^(id result, NSError *error) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    if ([result isKindOfClass:[NSString class]]) {
                        NSString *raw = (NSString *)result;
                        NSArray<NSString *> *parts = [raw componentsSeparatedByString:@";"];
                        for (NSString *part in parts) {
                            NSString *trimmed = [part stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
                            NSRange eq = [trimmed rangeOfString:@"="];
                            if (eq.location != NSNotFound && eq.location > 0) {
                                NSString *k = [trimmed substringToIndex:eq.location];
                                NSString *v = [trimmed substringFromIndex:eq.location + 1];
                                allMap[k] = trimmed;

                                NSString *dom = [currentHost containsString:@"amazon"] ? @".amazon.fr" : (currentHost.length > 0 ? currentHost : @".amazon.fr");
                                NSString *uKey = [NSString stringWithFormat:@"%@|/|%@", dom, k];
                                if (!rawPropMap[uKey]) {
                                    rawPropMap[uKey] = @{
                                        NSHTTPCookieName: k,
                                        NSHTTPCookieValue: v ?: @"",
                                        NSHTTPCookieDomain: dom,
                                        NSHTTPCookiePath: @"/",
                                        NSHTTPCookieExpires: [NSDate dateWithTimeIntervalSinceNow:86400 * 365],
                                        NSHTTPCookieSecure: @"TRUE"
                                    };
                                }

                                NSString *kLow = k.lowercaseString;
                                if ([currentHost containsString:@"amazon"] ||
                                    [kLow hasSuffix:@"acbfr"] ||
                                    [kLow isEqualToString:@"session-id"] ||
                                    [kLow isEqualToString:@"session-token"] ||
                                    [kLow isEqualToString:@"csm-hit"]) {
                                    amzMap[k] = trimmed;
                                }
                            }
                        }
                    }
                    dispatch_group_leave(grp);
                });
            }];
        }

        __block BOOL didCallback = NO;
        void (^finishBlock)(void) = ^{
            if (didCallback) return;
            didCallback = YES;
            if (completion) {
                completion([amzMap allValues], [allMap allValues], [rawPropMap allValues]);
            }
        };

        dispatch_group_notify(grp, dispatch_get_main_queue(), finishBlock);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.65 * NSEC_PER_SEC)), dispatch_get_main_queue(), finishBlock);
    });
}

// ============================================================================
// QUẢN LÝ SAO LƯU & KHÔI PHỤC TOÀN DIỆN (BACKUP & RESTORE MANAGER)
// ============================================================================
static NSString *GetSafariBackupRootDirectory(void) {
    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/SafariBackups"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return dir;
}

static NSArray<NSString *> *ListAvailableBackups(void) {
    NSString *root = GetSafariBackupRootDirectory();
    NSArray<NSString *> *items = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:root error:nil];
    if (!items) return @[];
    NSMutableArray<NSString *> *valid = [NSMutableArray array];
    for (NSString *item in items) {
        if ([item hasPrefix:@"BK_"]) {
            [valid addObject:item];
        }
    }
    [valid sortUsingComparator:^NSComparisonResult(NSString *a, NSString *b) {
        return [b compare:a]; // Mới nhất lên đầu
    }];
    return valid;
}

static void CloseAllSafariOpenTabsInRAM(void);
static void PurgeSafariDiskStorage(void);
static void PerformSafariDeepWipeAndRotate(BOOL shouldExitAfterWipe);

static void PerformFullSafariBackup(NSString *customLabel, BOOL wipeAfterBackup, void (^doneBlock)(NSString *folderPath, NSUInteger cookieCount)) {
    CollectAllSafariCookiesDetailed(^(NSArray<NSString *> *amzPairs, NSArray<NSString *> *allPairs, NSArray<NSDictionary *> *cookieDicts) {
        SWSpoofManager *sm = [SWSpoofManager shared];
        NSDateFormatter *df = [[NSDateFormatter alloc] init];
        df.dateFormat = @"yyyyMMdd_HHmmss";
        NSString *timeStr = [df stringFromDate:[NSDate date]];

        // Làm sạch nhãn ghi chú
        NSString *cleanTag = [[customLabel ?: @"" componentsSeparatedByCharactersInSet:[[NSCharacterSet alphanumericCharacterSet] invertedSet]] componentsJoinedByString:@"_"];
        if (cleanTag.length == 0) {
            cleanTag = [NSString stringWithFormat:@"%@_%@", sm.iosVersion ?: @"16.6", [sm.serial substringToIndex:MIN((NSUInteger)6, sm.serial.length)]];
        }

        NSString *folderName = [NSString stringWithFormat:@"BK_%@_%@_%luC", timeStr, cleanTag, (unsigned long)cookieDicts.count];
        NSString *targetDir = [GetSafariBackupRootDirectory() stringByAppendingPathComponent:folderName];
        NSFileManager *fm = [NSFileManager defaultManager];
        [fm createDirectoryAtPath:targetDir withIntermediateDirectories:YES attributes:nil error:nil];

        // 1. Lưu cấu hình Spoof Profile hiện tại
        [sm saveProfile];
        [fm copyItemAtPath:[sm profilePath] toPath:[targetDir stringByAppendingPathComponent:@"_spoof_profile.plist"] error:nil];

        // 2. Lưu mảng NSHTTPCookie đầy đủ thuộc tính (bao gồm HttpOnly)
        [cookieDicts writeToFile:[targetDir stringByAppendingPathComponent:@"_cookies_full.plist"] atomically:YES];

        // 3. Lưu chuỗi Cookie dạng text dễ copy
        NSString *amzTxt = [amzPairs componentsJoinedByString:@"; "];
        NSString *allTxt = [allPairs componentsJoinedByString:@"; "];
        [(amzTxt.length > 0 ? amzTxt : allTxt) writeToFile:[targetDir stringByAppendingPathComponent:@"_cookies_header.txt"] atomically:YES encoding:NSUTF8StringEncoding error:nil];

        // 4. Trích xuất localStorage, sessionStorage và URL từ WKWebView đang mở
        NSSet<WKWebView *> *webViews = GetAllActiveSafariWebViews();
        WKWebView *activeWV = [webViews anyObject];
        for (WKWebView *wv in webViews) {
            if ([wv.URL.host.lowercaseString containsString:@"amazon"]) {
                activeWV = wv;
                break;
            }
        }

        void (^finishDiskArchive)(NSString *, NSString *) = ^(NSString *webStorageJSON, NSString *currentURL) {
            if (webStorageJSON.length > 0) {
                [webStorageJSON writeToFile:[targetDir stringByAppendingPathComponent:@"_webstorage.json"] atomically:YES encoding:NSUTF8StringEncoding error:nil];
            }
            NSDictionary *meta = @{
                @"backup_name": folderName,
                @"created_at": [[NSDate date] description],
                @"url": currentURL ?: @"https://www.amazon.fr/",
                @"ios_version": sm.iosVersion ?: @"",
                @"user_agent": sm.userAgent ?: @"",
                @"idfv": sm.idfv ?: @"",
                @"idfa": sm.idfa ?: @"",
                @"serial": sm.serial ?: @"",
                @"canvas_seed": @(sm.canvasSeed),
                @"carrier": sm.carrierName ?: @"",
                @"amz_cookie_count": @(amzPairs.count),
                @"total_cookie_count": @(cookieDicts.count)
            };
            NSData *metaData = [NSJSONSerialization dataWithJSONObject:meta options:NSJSONWritingPrettyPrinted error:nil];
            [metaData writeToFile:[targetDir stringByAppendingPathComponent:@"_meta.json"] atomically:YES];

            // 5. Nén thêm thư mục Library/Cookies, Library/WebKit, Library/Safari trên đĩa
            NSString *tarFile = [targetDir stringByAppendingPathComponent:@"disk_storage.tar.gz"];
            const char *tarBins[] = {"/var/jb/usr/bin/tar", "/usr/bin/tar", NULL};
            char *tarArgv[] = {
                (char *)"tar",
                (char *)"-czf",
                (char *)[tarFile UTF8String],
                (char *)"-C",
                (char *)[NSHomeDirectory() UTF8String],
                (char *)"Library/Cookies",
                (char *)"Library/WebKit",
                (char *)"Library/Safari",
                NULL
            };
            RunCommandAndWait(tarBins, tarArgv);

            // Copyパス vào Clipboard để AutoTouch / người dùng dễ kiểm tra
            [UIPasteboard generalPasteboard].string = targetDir;

            if (doneBlock) {
                doneBlock(targetDir, cookieDicts.count);
            }
            if (wipeAfterBackup) {
                PerformSafariDeepWipeAndRotate(YES);
            }
        };

        if (activeWV) {
            NSString *curURL = activeWV.URL.absoluteString ?: @"https://www.amazon.fr/";
            NSString *dumpJS = @"(function(){try{var ls={},ss={};for(var i=0;i<localStorage.length;i++){var k=localStorage.key(i);ls[k]=localStorage.getItem(k);}for(var j=0;j<sessionStorage.length;j++){var k2=sessionStorage.key(j);ss[k2]=sessionStorage.getItem(k2);}return JSON.stringify({ls:ls,ss:ss});}catch(e){return '';}})();";
            [activeWV evaluateJavaScript:dumpJS completionHandler:^(id res, NSError *err) {
                NSString *jsonStr = [res isKindOfClass:[NSString class]] ? (NSString *)res : @"";
                finishDiskArchive(jsonStr, curURL);
            }];
        } else {
            finishDiskArchive(@"", @"https://www.amazon.fr/");
        }
    });
}

static void PerformFullSafariRestore(NSString *backupFolderName) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *sourceDir = [GetSafariBackupRootDirectory() stringByAppendingPathComponent:backupFolderName];
        NSFileManager *fm = [NSFileManager defaultManager];
        if (![fm fileExistsAtPath:sourceDir]) return;

        // 1. Đóng toàn bộ Tab hiện tại và xóa sạch dữ liệu phiên cũ
        CloseAllSafariOpenTabsInRAM();
        PurgeSafariDiskStorage();

        // 2. Khôi phục file cấu hình Spoof Profile (IDFV, Serial, Canvas Seed, UA)
        NSString *savedSpoofPath = [sourceDir stringByAppendingPathComponent:@"_spoof_profile.plist"];
        NSString *activeSpoofPath = [[SWSpoofManager shared] profilePath];
        if ([fm fileExistsAtPath:savedSpoofPath]) {
            [fm removeItemAtPath:activeSpoofPath error:nil];
            [fm copyItemAtPath:savedSpoofPath toPath:activeSpoofPath error:nil];
            [[SWSpoofManager shared] loadOrGenerateProfile];
        }

        // Đọc _webstorage.json và _meta.json để tự động bơm lại vào trang khi mở Safari
        NSString *wsPath = [sourceDir stringByAppendingPathComponent:@"_webstorage.json"];
        NSString *wsJSON = [NSString stringWithContentsOfFile:wsPath encoding:NSUTF8StringEncoding error:nil];
        NSData *metaData = [NSData dataWithContentsOfFile:[sourceDir stringByAppendingPathComponent:@"_meta.json"]];
        NSDictionary *meta = metaData ? [NSJSONSerialization JSONObjectWithData:metaData options:0 error:nil] : nil;
        NSString *restoreURL = meta[@"url"] ?: @"https://www.amazon.fr/";

        [SWSpoofManager shared].pendingRestoreWebStorageJSON = wsJSON;
        [SWSpoofManager shared].pendingRestoreURL = restoreURL;
        [[SWSpoofManager shared] saveProfile];

        // 3. Giải nén lại thư mục Library/Cookies, Library/WebKit, Library/Safari
        NSString *tarFile = [sourceDir stringByAppendingPathComponent:@"disk_storage.tar.gz"];
        if ([fm fileExistsAtPath:tarFile]) {
            const char *tarBins[] = {"/var/jb/usr/bin/tar", "/usr/bin/tar", NULL};
            char *tarArgv[] = {
                (char *)"tar",
                (char *)"-xzf",
                (char *)[tarFile UTF8String],
                (char *)"-C",
                (char *)[NSHomeDirectory() UTF8String],
                NULL
            };
            RunCommandAndWait(tarBins, tarArgv);
        }

        // 4. Nạp lại toàn bộ đối tượng NSHTTPCookie vào cả NSHTTPCookieStorage lẫn WKHTTPCookieStore
        NSString *cookiesPlist = [sourceDir stringByAppendingPathComponent:@"_cookies_full.plist"];
        NSArray<NSDictionary *> *cookieDicts = [NSArray arrayWithContentsOfFile:cookiesPlist];
        WKHTTPCookieStore *wkStore = [WKWebsiteDataStore defaultDataStore].httpCookieStore;
        NSHTTPCookieStorage *nsStore = [NSHTTPCookieStorage sharedHTTPCookieStorage];

        dispatch_group_t grp = dispatch_group_create();
        for (NSDictionary *props in cookieDicts) {
            NSHTTPCookie *cookie = [NSHTTPCookie cookieWithProperties:props];
            if (cookie) {
                [nsStore setCookie:cookie];
                dispatch_group_enter(grp);
                [wkStore setCookie:cookie completionHandler:^{
                    dispatch_group_leave(grp);
                }];
            }
        }

        // Sau khi nạp xong Cookie vào Store thì đóng Safari để khởi động sạch với Profile vừa Restore
        dispatch_group_notify(grp, dispatch_get_main_queue(), ^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                _exit(0);
            });
        });
    });
}

// Tự động nạp lại Cookie và WebStorage sau khi vừa Restore và mở lại Safari
static void CheckAndApplyPendingRestoreIfNeeded(WKWebView *webView) {
    SWSpoofManager *sm = [SWSpoofManager shared];
    if (!sm.pendingRestoreURL && !sm.pendingRestoreWebStorageJSON) return;

    NSString *wsJSON = sm.pendingRestoreWebStorageJSON;
    NSString *targetURL = sm.pendingRestoreURL;

    // Xóa cờ chờ để chỉ chạy 1 lần duy nhất
    sm.pendingRestoreWebStorageJSON = nil;
    sm.pendingRestoreURL = nil;
    [sm saveProfile];

    if (wsJSON.length > 2 && webView.configuration.userContentController) {
        NSString *restoreJS = [NSString stringWithFormat:
            @"(function(){try{var d=%@;if(d&&d.ls){for(var k in d.ls){localStorage.setItem(k,d.ls[k]);}}if(d&&d.ss){for(var k2 in d.ss){sessionStorage.setItem(k2,d.ss[k2]);}}}catch(e){}})();",
            wsJSON];
        WKUserScript *wsScript = [[WKUserScript alloc] initWithSource:restoreJS
                                                        injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                                                     forMainFrameOnly:YES];
        [webView.configuration.userContentController addUserScript:wsScript];
    }

    if (targetURL.length > 0) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            NSURL *u = [NSURL URLWithString:targetURL];
            if (u) {
                [webView loadRequest:[NSURLRequest requestWithURL:u]];
            }
        });
    }
}

static IMP orig_WKWebView_initWithFrameConfig = NULL;
static IMP orig_WKWebView_setCustomUA = NULL;
static IMP orig_WKWebView_loadRequest = NULL;
static IMP orig_WKUCC_removeAllUserScripts = NULL;
static IMP orig_UIDevice_idfv = NULL;
static IMP orig_UIDevice_systemVersion = NULL;

static WKWebView* swizzled_WKWebView_initWithFrameConfig(WKWebView *self, SEL _cmd, CGRect frame, WKWebViewConfiguration *configuration) {
    if (configuration) {
        if (!configuration.userContentController) {
            configuration.userContentController = [[WKUserContentController alloc] init];
        }
        [[SWSpoofManager shared] injectIntoUserContentController:configuration.userContentController];
    }
    WKWebView *webView = ((WKWebView* (*)(id, SEL, CGRect, WKWebViewConfiguration *))orig_WKWebView_initWithFrameConfig)(self, _cmd, frame, configuration);
    if (webView) {
        TrackWebView(webView);
        [[SWSpoofManager shared] injectIntoUserContentController:webView.configuration.userContentController];
        NSString *spoofedUA = [SWSpoofManager shared].userAgent;
        if (spoofedUA.length > 0 && orig_WKWebView_setCustomUA) {
            ((void (*)(id, SEL, NSString *))orig_WKWebView_setCustomUA)(webView, @selector(setCustomUserAgent:), spoofedUA);
        }
        CheckAndApplyPendingRestoreIfNeeded(webView);
    }
    return webView;
}

static void swizzled_WKUCC_removeAllUserScripts(WKUserContentController *self, SEL _cmd) {
    ((void (*)(id, SEL))orig_WKUCC_removeAllUserScripts)(self, _cmd);
    [[SWSpoofManager shared] injectIntoUserContentController:self];
}

static void swizzled_WKWebView_setCustomUA(WKWebView *self, SEL _cmd, NSString *customUserAgent) {
    TrackWebView(self);
    NSString *spoofedUA = [SWSpoofManager shared].userAgent;
    if (customUserAgent && [customUserAgent containsString:@"Macintosh"]) {
        ((void (*)(id, SEL, NSString *))orig_WKWebView_setCustomUA)(self, _cmd, customUserAgent);
    } else if (spoofedUA.length > 0) {
        ((void (*)(id, SEL, NSString *))orig_WKWebView_setCustomUA)(self, _cmd, spoofedUA);
    } else {
        ((void (*)(id, SEL, NSString *))orig_WKWebView_setCustomUA)(self, _cmd, customUserAgent);
    }
}

static WKNavigation* swizzled_WKWebView_loadRequest(WKWebView *self, SEL _cmd, NSURLRequest *request) {
    TrackWebView(self);
    [[SWSpoofManager shared] injectIntoUserContentController:self.configuration.userContentController];
    return ((WKNavigation* (*)(id, SEL, NSURLRequest *))orig_WKWebView_loadRequest)(self, _cmd, request);
}

static NSUUID* swizzled_UIDevice_idfv(UIDevice *self, SEL _cmd) {
    NSString *idfvStr = [SWSpoofManager shared].idfv;
    if (idfvStr.length > 0) {
        NSUUID *uuid = [[NSUUID alloc] initWithUUIDString:idfvStr];
        if (uuid) return uuid;
    }
    return ((NSUUID* (*)(id, SEL))orig_UIDevice_idfv)(self, _cmd);
}

static NSString* swizzled_UIDevice_systemVersion(UIDevice *self, SEL _cmd) {
    NSString *ver = [SWSpoofManager shared].iosVersion;
    if (ver.length > 0) return ver;
    return ((NSString* (*)(id, SEL))orig_UIDevice_systemVersion)(self, _cmd);
}

static NSLocale* swizzled_NSLocale_current(id self, SEL _cmd) {
    return [NSLocale localeWithLocaleIdentifier:@"fr_FR"];
}
static NSArray* swizzled_NSLocale_preferredLanguages(id self, SEL _cmd) {
    return @[@"fr-FR", @"fr"];
}
static NSTimeZone* swizzled_NSTimeZone_local(id self, SEL _cmd) {
    return [NSTimeZone timeZoneWithName:@"Europe/Paris"];
}
static NSString* swizzled_CTCarrier_name(CTCarrier *self, SEL _cmd) {
    return [SWSpoofManager shared].carrierName ?: @"Orange F";
}
static NSString* swizzled_CTCarrier_iso(CTCarrier *self, SEL _cmd) {
    return [SWSpoofManager shared].carrierISO ?: @"fr";
}
static NSString* swizzled_CTCarrier_mcc(CTCarrier *self, SEL _cmd) {
    return [SWSpoofManager shared].carrierMCC ?: @"208";
}
static NSString* swizzled_CTCarrier_mnc(CTCarrier *self, SEL _cmd) {
    return [SWSpoofManager shared].carrierMNC ?: @"01";
}

static void InstallSafariHooks(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        Method mInit = class_getInstanceMethod([WKWebView class], @selector(initWithFrame:configuration:));
        if (mInit) orig_WKWebView_initWithFrameConfig = method_setImplementation(mInit, (IMP)swizzled_WKWebView_initWithFrameConfig);

        Method mRemUS = class_getInstanceMethod([WKUserContentController class], @selector(removeAllUserScripts));
        if (mRemUS) orig_WKUCC_removeAllUserScripts = method_setImplementation(mRemUS, (IMP)swizzled_WKUCC_removeAllUserScripts);

        Method mSetUA = class_getInstanceMethod([WKWebView class], @selector(setCustomUserAgent:));
        if (mSetUA) orig_WKWebView_setCustomUA = method_setImplementation(mSetUA, (IMP)swizzled_WKWebView_setCustomUA);

        Method mLoadReq = class_getInstanceMethod([WKWebView class], @selector(loadRequest:));
        if (mLoadReq) orig_WKWebView_loadRequest = method_setImplementation(mLoadReq, (IMP)swizzled_WKWebView_loadRequest);

        Method mIdfv = class_getInstanceMethod([UIDevice class], @selector(identifierForVendor));
        if (mIdfv) orig_UIDevice_idfv = method_setImplementation(mIdfv, (IMP)swizzled_UIDevice_idfv);

        Method mSysVer = class_getInstanceMethod([UIDevice class], @selector(systemVersion));
        if (mSysVer) orig_UIDevice_systemVersion = method_setImplementation(mSysVer, (IMP)swizzled_UIDevice_systemVersion);

        Method mLocCur = class_getClassMethod([NSLocale class], @selector(currentLocale));
        if (mLocCur) method_setImplementation(mLocCur, (IMP)swizzled_NSLocale_current);
        Method mLocAuto = class_getClassMethod([NSLocale class], @selector(autoupdatingCurrentLocale));
        if (mLocAuto) method_setImplementation(mLocAuto, (IMP)swizzled_NSLocale_current);
        Method mLocPref = class_getClassMethod([NSLocale class], @selector(preferredLanguages));
        if (mLocPref) method_setImplementation(mLocPref, (IMP)swizzled_NSLocale_preferredLanguages);

        Method mTzLocal = class_getClassMethod([NSTimeZone class], @selector(localTimeZone));
        if (mTzLocal) method_setImplementation(mTzLocal, (IMP)swizzled_NSTimeZone_local);
        Method mTzSys = class_getClassMethod([NSTimeZone class], @selector(systemTimeZone));
        if (mTzSys) method_setImplementation(mTzSys, (IMP)swizzled_NSTimeZone_local);

        Method mCarName = class_getInstanceMethod([CTCarrier class], @selector(carrierName));
        if (mCarName) method_setImplementation(mCarName, (IMP)swizzled_CTCarrier_name);
        Method mCarIso = class_getInstanceMethod([CTCarrier class], @selector(isoCountryCode));
        if (mCarIso) method_setImplementation(mCarIso, (IMP)swizzled_CTCarrier_iso);
        Method mCarMcc = class_getInstanceMethod([CTCarrier class], @selector(mobileCountryCode));
        if (mCarMcc) method_setImplementation(mCarMcc, (IMP)swizzled_CTCarrier_mcc);
        Method mCarMnc = class_getInstanceMethod([CTCarrier class], @selector(mobileNetworkCode));
        if (mCarMnc) method_setImplementation(mCarMnc, (IMP)swizzled_CTCarrier_mnc);
    });
}

@interface SWFloatingWindow : UIWindow
@property (nonatomic, strong) UIButton *fabButton;
@end

@implementation SWFloatingWindow
- (BOOL)pointInside:(CGPoint)point withEvent:(UIEvent *)event {
    if (self.rootViewController && self.rootViewController.presentedViewController) {
        return [super pointInside:point withEvent:event];
    }
    if (!self.fabButton || self.fabButton.hidden) return NO;
    CGPoint buttonPoint = [self convertPoint:point toView:self.fabButton];
    return [self.fabButton pointInside:buttonPoint withEvent:event];
}
@end

static SWFloatingWindow *gOverlayWindow = nil;
static NSTimer *gCheckTimer = nil;

static void CloseAllSafariOpenTabsInRAM(void) {
    @try {
        id app = [UIApplication sharedApplication];
        id appDelegate = [app delegate];
        NSArray *controllers = nil;
        if ([app respondsToSelector:NSSelectorFromString(@"browserControllers")]) {
            controllers = [app valueForKey:@"browserControllers"];
        } else if (appDelegate && [appDelegate respondsToSelector:NSSelectorFromString(@"browserControllers")]) {
            controllers = [appDelegate valueForKey:@"browserControllers"];
        }

        for (id bc in controllers) {
            if ([bc respondsToSelector:NSSelectorFromString(@"tabController")]) {
                id tc = [bc valueForKey:@"tabController"];
                if (tc) {
                    SEL sel1 = NSSelectorFromString(@"closeAllOpenTabsAnimated:");
                    SEL sel2 = NSSelectorFromString(@"closeAllOpenTabs");
                    if ([tc respondsToSelector:sel1]) {
                        ((void (*)(id, SEL, BOOL))objc_msgSend)(tc, sel1, NO);
                    } else if ([tc respondsToSelector:sel2]) {
                        ((void (*)(id, SEL))objc_msgSend)(tc, sel2);
                    }
                }
            }
        }
    } @catch (NSException *e) {}
}

static void PurgeSafariDiskStorage(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *home = NSHomeDirectory();

    NSArray *sandboxPaths = @[
        @"Library/Caches",
        @"Library/Cookies",
        @"Library/WebKit",
        @"Library/Safari",
        @"Library/Saved Application State",
        @"Library/SplashBoard/Snapshots",
        @"SystemData/com.apple.SafariViewService",
        @"tmp"
    ];
    for (NSString *rel in sandboxPaths) {
        NSString *full = [home stringByAppendingPathComponent:rel];
        NSArray *items = [fm contentsOfDirectoryAtPath:full error:nil];
        for (NSString *item in items) {
            [fm removeItemAtPath:[full stringByAppendingPathComponent:item] error:nil];
        }
    }

    NSArray *globalSafariDirs = @[
        @"/var/mobile/Library/Safari",
        @"/var/mobile/Library/WebKit",
        @"/var/mobile/Library/Caches/com.apple.mobilesafari",
        @"/var/mobile/Library/Caches/com.apple.SharedWebCredentials"
    ];
    for (NSString *dir in globalSafariDirs) {
        NSArray *items = [fm contentsOfDirectoryAtPath:dir error:nil];
        for (NSString *f in items) {
            if ([f containsString:@"BrowserState"] ||
                [f containsString:@"SafariTabs"] ||
                [f containsString:@"LastSession"] ||
                [f containsString:@"SuspendedState"] ||
                [f containsString:@"CloudTabs"] ||
                [f containsString:@"Thumbnails"] ||
                [f containsString:@"History"] ||
                [f containsString:@"SharedWebCredentials"]) {
                [fm removeItemAtPath:[dir stringByAppendingPathComponent:f] error:nil];
            }
        }
    }

    NSString *appGroupRoot = @"/var/mobile/Containers/Shared/AppGroup";
    NSArray *groups = [fm contentsOfDirectoryAtPath:appGroupRoot error:nil];
    for (NSString *g in groups) {
        NSString *safariGroupDir = [[appGroupRoot stringByAppendingPathComponent:g] stringByAppendingPathComponent:@"Library/Safari"];
        if ([fm fileExistsAtPath:safariGroupDir]) {
            NSArray *gItems = [fm contentsOfDirectoryAtPath:safariGroupDir error:nil];
            for (NSString *gf in gItems) {
                if ([gf containsString:@"BrowserState"] || [gf containsString:@"SafariTabs"] || [gf containsString:@"LastSession"]) {
                    [fm removeItemAtPath:[safariGroupDir stringByAppendingPathComponent:gf] error:nil];
                }
            }
        }
    }

    NSArray *sharedCookieFiles = [fm contentsOfDirectoryAtPath:@"/var/mobile/Library/Cookies" error:nil];
    for (NSString *f in sharedCookieFiles) {
        if ([f containsString:@"Cookies"] || [f containsString:@"safari"]) {
            [fm removeItemAtPath:[@"/var/mobile/Library/Cookies" stringByAppendingPathComponent:f] error:nil];
        }
    }
}

static void FinalizeHardExit(BOOL shouldExitAfterWipe) {
    CloseAllSafariOpenTabsInRAM();
    [[SWSpoofManager shared] rotateProfile];
    PurgeSafariDiskStorage();
    KillBackgroundWebKitDaemons();

    if (shouldExitAfterWipe) {
        _exit(0);
    }
}

static void PerformSafariDeepWipeAndRotate(BOOL shouldExitAfterWipe) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gOverlayWindow && gOverlayWindow.fabButton) {
            [gOverlayWindow.fabButton setTitle:@"..." forState:UIControlStateNormal];
            gOverlayWindow.fabButton.backgroundColor = [UIColor darkGrayColor];
            gOverlayWindow.fabButton.userInteractionEnabled = NO;
        }

        NSMutableSet<WKWebsiteDataStore *> *allDataStores = [NSMutableSet set];
        if ([WKWebsiteDataStore defaultDataStore]) {
            [allDataStores addObject:[WKWebsiteDataStore defaultDataStore]];
        }
        for (WKWebView *wv in GetAllActiveSafariWebViews()) {
            if (wv.configuration.websiteDataStore) {
                [allDataStores addObject:wv.configuration.websiteDataStore];
            }
            [wv evaluateJavaScript:@"try{localStorage.clear();sessionStorage.clear();}catch(e){}" completionHandler:nil];
        }

        CloseAllSafariOpenTabsInRAM();

        NSArray *secClasses = @[
            (__bridge id)kSecClassGenericPassword,
            (__bridge id)kSecClassInternetPassword,
            (__bridge id)kSecClassCertificate,
            (__bridge id)kSecClassKey,
            (__bridge id)kSecClassIdentity
        ];
        for (id secClass in secClasses) {
            NSDictionary *q1 = @{(__bridge id)kSecClass: secClass, (__bridge id)kSecAttrSynchronizable: (__bridge id)kSecAttrSynchronizableAny};
            SecItemDelete((__bridge CFDictionaryRef)q1);
            NSDictionary *q2 = @{(__bridge id)kSecClass: secClass};
            SecItemDelete((__bridge CFDictionaryRef)q2);
        }

        NSHTTPCookieStorage *cs = [NSHTTPCookieStorage sharedHTTPCookieStorage];
        for (NSHTTPCookie *c in [cs cookies]) { [cs deleteCookie:c]; }
        [[NSURLCache sharedURLCache] removeAllCachedResponses];

        NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
        if (bid) {
            [[NSUserDefaults standardUserDefaults] removePersistentDomainForName:bid];
            [[NSUserDefaults standardUserDefaults] synchronize];
        }

        PurgeSafariDiskStorage();

        if (shouldExitAfterWipe) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                FinalizeHardExit(YES);
            });
        }

        NSSet *allTypes = [WKWebsiteDataStore allWebsiteDataTypes];
        NSDate *epoch = [NSDate dateWithTimeIntervalSince1970:0];
        dispatch_group_t wipeGrp = dispatch_group_create();

        for (WKWebsiteDataStore *ds in allDataStores) {
            dispatch_group_enter(wipeGrp);
            [ds.httpCookieStore getAllCookies:^(NSArray<NSHTTPCookie *> *wkCookies) {
                for (NSHTTPCookie *c in wkCookies) {
                    [ds.httpCookieStore deleteCookie:c completionHandler:nil];
                }
                [ds removeDataOfTypes:allTypes modifiedSince:epoch completionHandler:^{
                    dispatch_group_leave(wipeGrp);
                }];
            }];
        }

        dispatch_group_notify(wipeGrp, dispatch_get_main_queue(), ^{
            FinalizeHardExit(shouldExitAfterWipe);
        });
    });
}

@interface SWFloatingController : NSObject
+ (instancetype)shared;
- (void)tryAttachButton;
- (void)applyButtonAppearance;
- (void)showMainPanel;
- (void)showBackupManagerMenu;
@end

@implementation SWFloatingController
+ (instancetype)shared {
    static SWFloatingController *inst = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ inst = [[self alloc] init]; });
    return inst;
}

- (void)applyButtonAppearance {
    if (!gOverlayWindow || !gOverlayWindow.fabButton) return;
    UIButton *btn = gOverlayWindow.fabButton;
    BOOL visible = [SWSpoofManager shared].isButtonVisible;

    if (visible) {
        btn.backgroundColor = [UIColor colorWithRed:0.85 green:0.14 blue:0.18 alpha:0.92];
        [btn setTitle:[NSString stringWithFormat:@"WIPE\n%@", [SWSpoofManager shared].iosVersion] forState:UIControlStateNormal];
        [btn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        btn.layer.borderWidth = 2.0;
        btn.layer.borderColor = [UIColor whiteColor].CGColor;
    } else {
        btn.backgroundColor = [UIColor clearColor];
        [btn setTitle:@"" forState:UIControlStateNormal];
        [btn setTitleColor:[UIColor clearColor] forState:UIControlStateNormal];
        btn.layer.borderWidth = 0.0;
        btn.layer.borderColor = [UIColor clearColor].CGColor;
    }
}

- (void)tryAttachButton {
    if (gOverlayWindow != nil && gOverlayWindow.windowScene != nil && !gOverlayWindow.hidden) {
        return;
    }
    UIApplication *app = [UIApplication sharedApplication];
    if (!app) return;

    UIWindowScene *activeScene = nil;
    for (UIScene *scene in app.connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]]) {
            UIWindowScene *ws = (UIWindowScene *)scene;
            if (ws.activationState == UISceneActivationStateForegroundActive || ws.activationState == UISceneActivationStateForegroundInactive) {
                activeScene = ws;
                break;
            }
            if (!activeScene) activeScene = ws;
        }
    }

    if (!activeScene) return;

    for (UIWindow *win in activeScene.windows) {
        if (![win isKindOfClass:[SWFloatingWindow class]] && win.gestureRecognizers.count < 15) {
            BOOL hasTripleTap = NO;
            for (UIGestureRecognizer *gr in win.gestureRecognizers) {
                if ([gr isKindOfClass:[UITapGestureRecognizer class]] && ((UITapGestureRecognizer *)gr).numberOfTouchesRequired == 3) {
                    hasTripleTap = YES;
                    break;
                }
            }
            if (!hasTripleTap) {
                UITapGestureRecognizer *tripleTap = [[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(onTripleFingerTap:)];
                tripleTap.numberOfTouchesRequired = 3;
                tripleTap.numberOfTapsRequired = 1;
                [win addGestureRecognizer:tripleTap];
            }
        }
    }

    CGRect bounds = [UIScreen mainScreen].bounds;
    gOverlayWindow = [[SWFloatingWindow alloc] initWithWindowScene:activeScene];
    gOverlayWindow.frame = bounds;

    UIViewController *vc = [[UIViewController alloc] init];
    vc.view.backgroundColor = [UIColor clearColor];
    gOverlayWindow.rootViewController = vc;
    gOverlayWindow.backgroundColor = [UIColor clearColor];
    gOverlayWindow.windowLevel = UIWindowLevelAlert + 500.0;
    gOverlayWindow.hidden = NO;

    CGFloat sz = 56.0;
    UIButton *btn = [UIButton buttonWithType:UIButtonTypeCustom];
    btn.frame = CGRectMake(bounds.size.width - sz - 12.0, 160.0, sz, sz);
    btn.titleLabel.numberOfLines = 2;
    btn.titleLabel.textAlignment = NSTextAlignmentCenter;
    btn.titleLabel.font = [UIFont systemFontOfSize:10.5 weight:UIFontWeightHeavy];
    btn.layer.cornerRadius = sz / 2.0;

    [btn addTarget:self action:@selector(onWipeTapped:) forControlEvents:UIControlEventTouchUpInside];

    UILongPressGestureRecognizer *longPress = [[UILongPressGestureRecognizer alloc] initWithTarget:self action:@selector(onLongPressed:)];
    longPress.minimumPressDuration = 0.5;
    [btn addGestureRecognizer:longPress];

    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(onPanned:)];
    [btn addGestureRecognizer:pan];

    [vc.view addSubview:btn];
    gOverlayWindow.fabButton = btn;

    [self applyButtonAppearance];

    if (gCheckTimer) {
        [gCheckTimer invalidate];
        gCheckTimer = nil;
    }
}

- (void)onWipeTapped:(UIButton *)sender {
    PerformSafariDeepWipeAndRotate(YES);
}

- (void)onTripleFingerTap:(UITapGestureRecognizer *)tap {
    if (tap.state == UIGestureRecognizerStateEnded) {
        [self showMainPanel];
    }
}

- (void)onLongPressed:(UILongPressGestureRecognizer *)lp {
    if (lp.state == UIGestureRecognizerStateBegan) {
        [self showMainPanel];
    }
}

// ============================================================================
// MENU QUẢN LÝ SAO LƯU & KHÔI PHỤC (BACKUP & RESTORE SUB-MENU)
// ============================================================================
- (void)promptCustomLabelAndBackupWithWipe:(BOOL)wipeAfter {
    UIAlertController *prompt = [UIAlertController alertControllerWithTitle:wipeAfter ? @"Sao lưu & Wipe sang máy mới" : @"Sao lưu toàn bộ phiên hiện tại"
                                                                    message:@"Nhập tên gợi nhớ (VD: AccPhap01, Mail...) hoặc để trống để tự đặt theo Serial:"
                                                             preferredStyle:UIAlertControllerStyleAlert];
    [prompt addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"Tên phiên sao lưu (tùy chọn)";
    }];

    [prompt addAction:[UIAlertAction actionWithTitle:@"Bắt đầu Sao lưu" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *tag = prompt.textFields.firstObject.text;
        PerformFullSafariBackup(tag, wipeAfter, ^(NSString *folderPath, NSUInteger cookieCount) {
            if (!wipeAfter && gOverlayWindow && gOverlayWindow.rootViewController) {
                NSString *shortName = [folderPath lastPathComponent];
                UIAlertController *doneAlert = [UIAlertController alertControllerWithTitle:@"Đã Sao Lưu Thành Công!"
                                                                                   message:[NSString stringWithFormat:@"• Gói: %@\n• Đã lưu: %lu Cookies + LocalStorage + Hồ sơ máy (%@)\n• Đường dẫn đã được Copy vào bộ nhớ tạm.", shortName, (unsigned long)cookieCount, [SWSpoofManager shared].iosVersion]
                                                                            preferredStyle:UIAlertControllerStyleAlert];
                [doneAlert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
                [gOverlayWindow.rootViewController presentViewController:doneAlert animated:YES completion:nil];
            }
        });
    }]];

    [prompt addAction:[UIAlertAction actionWithTitle:@"Hủy" style:UIAlertActionStyleCancel handler:nil]];
    if (gOverlayWindow && gOverlayWindow.rootViewController) {
        [gOverlayWindow.rootViewController presentViewController:prompt animated:YES completion:nil];
    }
}

- (void)showActionForSingleBackup:(NSString *)folderName {
    NSString *fullPath = [GetSafariBackupRootDirectory() stringByAppendingPathComponent:folderName];
    NSData *metaData = [NSData dataWithContentsOfFile:[fullPath stringByAppendingPathComponent:@"_meta.json"]];
    NSDictionary *meta = metaData ? [NSJSONSerialization JSONObjectWithData:metaData options:0 error:nil] : @{};

    NSString *info = [NSString stringWithFormat:
        @"• Gói: %@\n"
        @"• Thời gian: %@\n"
        @"• iOS: %@ | Serial: %@\n"
        @"• Seed: #%@ | Nhà mạng: %@\n"
        @"• Cookie Amazon: %@ | Tổng: %@\n"
        @"• URL: %@",
        folderName,
        meta[@"created_at"] ?: @"N/A",
        meta[@"ios_version"] ?: @"16.6",
        meta[@"serial"] ?: @"N/A",
        meta[@"canvas_seed"] ?: @"N/A",
        meta[@"carrier"] ?: @"Orange F",
        meta[@"amz_cookie_count"] ?: @0,
        meta[@"total_cookie_count"] ?: @0,
        meta[@"url"] ?: @"https://www.amazon.fr/"];

    UIAlertController *sub = [UIAlertController alertControllerWithTitle:@"Chi tiết Bản Sao Lưu"
                                                                 message:info
                                                          preferredStyle:UIAlertControllerStyleAlert];

    [sub addAction:[UIAlertAction actionWithTitle:@"Khôi phục (Restore) phiên này & Mở lại" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        PerformFullSafariRestore(folderName);
    }]];

    [sub addAction:[UIAlertAction actionWithTitle:@"Copy chuỗi Cookie của bản này" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *cTxt = [NSString stringWithContentsOfFile:[fullPath stringByAppendingPathComponent:@"_cookies_header.txt"] encoding:NSUTF8StringEncoding error:nil];
        if (cTxt.length > 0) {
            [UIPasteboard generalPasteboard].string = cTxt;
        }
    }]];

    [sub addAction:[UIAlertAction actionWithTitle:@"Copy đường dẫn thư mục" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        [UIPasteboard generalPasteboard].string = fullPath;
    }]];

    [sub addAction:[UIAlertAction actionWithTitle:@"Xóa bản sao lưu này" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        [[NSFileManager defaultManager] removeItemAtPath:fullPath error:nil];
        [self showBackupManagerMenu];
    }]];

    [sub addAction:[UIAlertAction actionWithTitle:@"Quay lại" style:UIAlertActionStyleCancel handler:^(UIAlertAction *a) {
        [self showBackupManagerMenu];
    }]];

    if (gOverlayWindow && gOverlayWindow.rootViewController) {
        [gOverlayWindow.rootViewController presentViewController:sub animated:YES completion:nil];
    }
}

- (void)showBackupManagerMenu {
    NSArray<NSString *> *backups = ListAvailableBackups();
    NSString *msg = [NSString stringWithFormat:@"Thư mục: Documents/SafariBackups\nHiện có: %lu bản sao lưu toàn diện (Cookies + LocalStorage + Disk + Hồ sơ phần cứng)", (unsigned long)backups.count];

    UIAlertController *menu = [UIAlertController alertControllerWithTitle:@"Menu Sao Lưu & Khôi Phục (V7.1)"
                                                                  message:msg
                                                           preferredStyle:UIAlertControllerStyleAlert];

    [menu addAction:[UIAlertAction actionWithTitle:@"[+] Sao lưu phiên hiện tại (Giữ nguyên)" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        [self promptCustomLabelAndBackupWithWipe:NO];
    }]];

    [menu addAction:[UIAlertAction actionWithTitle:@"[+] Sao lưu xong & Tự động WIPE sang máy mới" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
        [self promptCustomLabelAndBackupWithWipe:YES];
    }]];

    // Hiển thị danh sách 10 bản sao lưu gần nhất để chọn Restore ngay
    NSUInteger limit = MIN(backups.count, (NSUInteger)10);
    for (NSUInteger i = 0; i < limit; i++) {
        NSString *folderName = backups[i];
        NSString *btnTitle = [NSString stringWithFormat:@"Restore: %@", folderName];
        [menu addAction:[UIAlertAction actionWithTitle:btnTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            [self showActionForSingleBackup:folderName];
        }]];
    }

    if (backups.count > 0) {
        [menu addAction:[UIAlertAction actionWithTitle:@"Xóa tất cả các bản sao lưu cũ" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
            NSString *root = GetSafariBackupRootDirectory();
            for (NSString *b in backups) {
                [[NSFileManager defaultManager] removeItemAtPath:[root stringByAppendingPathComponent:b] error:nil];
            }
        }]];
    }

    [menu addAction:[UIAlertAction actionWithTitle:@"Quay lại Menu chính" style:UIAlertActionStyleCancel handler:^(UIAlertAction *a) {
        [self showMainPanel];
    }]];

    if (gOverlayWindow && gOverlayWindow.rootViewController) {
        [gOverlayWindow.rootViewController presentViewController:menu animated:YES completion:nil];
    }
}

- (void)copyDiagnosticReportWithAmzCookies:(NSArray<NSString *> *)amzCookies allCookies:(NSArray<NSString *> *)allCookies {
    SWSpoofManager *sm = [SWSpoofManager shared];
    CGRect scr = [UIScreen mainScreen].bounds;
    CGFloat scale = [UIScreen mainScreen].scale;
    double memGB = (double)[NSProcessInfo processInfo].physicalMemory / (1024.0 * 1024.0 * 1024.0);

    NSArray<NSString *> *targetCookies = amzCookies.count > 0 ? amzCookies : allCookies;
    NSString *cookieBlock = targetCookies.count > 0 ? [targetCookies componentsJoinedByString:@"; "] : @"(no cookies)";
    NSString *report = [NSString stringWithFormat:
        @"=== SAFARI V7.1 DIAGNOSTIC (BACKUP SUITE) ===\n"
        @"Time: %@\n\n"
        @"--- IDENTITY ---\n"
        @"Spoofed IDFV:            %@\n"
        @"Spoofed IDFA:            %@\n"
        @"Spoofed Serial:          %@\n"
        @"Hardware Noise Seed:     #%ld\n\n"
        @"--- DEVICE ---\n"
        @"Model:                   iPhone (iOS %@)\n"
        @"Screen:                  %.0fx%.0f @%.0fx\n"
        @"PhysicalMemory:          %.1f GB\n"
        @"User-Agent:              %@\n\n"
        @"--- LOCALE / TZ ---\n"
        @"Locale:                  %@\n"
        @"Timezone:                %@\n\n"
        @"--- CARRIER ---\n"
        @"CarrierName:             %@\n"
        @"ISO / MCC / MNC:         %@ / %@ / %@\n\n"
        @"--- COOKIES (Amazon: %lu | Total: %lu) ---\n"
        @"%@\n",
        [[NSDate date] description],
        sm.idfv, sm.idfa, sm.serial, (long)sm.canvasSeed,
        sm.iosVersion, scr.size.width * scale, scr.size.height * scale, scale, memGB, sm.userAgent,
        sm.localeCode, sm.timeZoneName,
        sm.carrierName, sm.carrierISO, sm.carrierMCC, sm.carrierMNC,
        (unsigned long)amzCookies.count, (unsigned long)allCookies.count,
        cookieBlock];

    [UIPasteboard generalPasteboard].string = report;
}

- (void)showMainPanel {
    CollectAllSafariCookiesDetailed(^(NSArray<NSString *> *amzCookies, NSArray<NSString *> *allCookies, NSArray<NSDictionary *> *cookieDicts) {
        SWSpoofManager *sm = [SWSpoofManager shared];
        NSArray<NSString *> *savedBackups = ListAvailableBackups();
        NSString *bannerState = sm.forceAppBanner ? @"ĐANG BẬT (AutoTouch Ready)" : @"Đang tắt";
        NSString *msg = [NSString stringWithFormat:
            @"• Nhánh UA: iOS %@ (%ld Cores)\n"
            @"• HW Seed (WebGL/Canvas/Rect): #%ld\n"
            @"• Vùng: %@ | %@\n"
            @"• Nhà mạng: %@ (%@-%@)\n"
            @"• Cookie Amazon: %lu | Tổng Cookie: %lu\n"
            @"• Kho Backup: %lu bản đã lưu\n"
            @"• Banner Open: %@\n"
            @"• Serial: %@ | IDFV:\n%@\n\n"
            @"• User-Agent:\n%@",
            sm.iosVersion, (long)sm.cpuCores,
            (long)sm.canvasSeed,
            sm.localeCode, sm.timeZoneName,
            sm.carrierName, sm.carrierMCC, sm.carrierMNC,
            (unsigned long)amzCookies.count, (unsigned long)allCookies.count,
            (unsigned long)savedBackups.count,
            bannerState,
            sm.serial, sm.idfv,
            sm.userAgent];

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Safari Spoof V7.1 (Backup Suite)"
                                                                       message:msg
                                                                preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"Sao Lưu & Khôi Phục Full (%lu bản)", (unsigned long)savedBackups.count] style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            [self showBackupManagerMenu];
        }]];

        [alert addAction:[UIAlertAction actionWithTitle:@"Sao Lưu Nhanh & WIPE Sang Máy Mới" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
            PerformFullSafariBackup(@"AutoRun", YES, nil);
        }]];

        [alert addAction:[UIAlertAction actionWithTitle:@"Wipe Sạch Tab + swcd & Đổi Máy (Không lưu)" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
            PerformSafariDeepWipeAndRotate(YES);
        }]];

        NSString *toggleBannerTitle = sm.forceAppBanner ? @"Banner Open: Đang BẬT (Bấm để Tắt)" : @"Banner Open: Đang TẮT (Bấm để Bật)";
        [alert addAction:[UIAlertAction actionWithTitle:toggleBannerTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            sm.forceAppBanner = !sm.forceAppBanner;
            [sm saveProfile];
        }]];

        if (amzCookies.count > 0) {
            [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"Cookies: Copy Amazon.fr (%lu)", (unsigned long)amzCookies.count] style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                [UIPasteboard generalPasteboard].string = [amzCookies componentsJoinedByString:@"; "];
            }]];
        }

        [alert addAction:[UIAlertAction actionWithTitle:@"Info: Copy Diagnostic Report" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            [self copyDiagnosticReportWithAmzCookies:amzCookies allCookies:allCookies];
        }]];

        NSString *visTitle = sm.isButtonVisible ? @"Chế độ: Ẩn nút nổi (Stealth)" : @"Chế độ: Hiện lại nút nổi";
        [alert addAction:[UIAlertAction actionWithTitle:visTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
            sm.isButtonVisible = !sm.isButtonVisible;
            [sm saveProfile];
            [self applyButtonAppearance];
        }]];

        [alert addAction:[UIAlertAction actionWithTitle:@"Đóng" style:UIAlertActionStyleCancel handler:nil]];

        if (gOverlayWindow && gOverlayWindow.rootViewController) {
            [gOverlayWindow.rootViewController presentViewController:alert animated:YES completion:nil];
        }
    });
}

- (void)onPanned:(UIPanGestureRecognizer *)pan {
    UIView *btn = pan.view;
    if (!btn || !btn.superview) return;
    CGPoint trans = [pan translationInView:btn.superview];
    btn.center = CGPointMake(btn.center.x + trans.x, btn.center.y + trans.y);
    [pan setTranslation:CGPointZero inView:btn.superview];
}
@end

__attribute__((constructor))
static void SafariWipeInit(void) {
    @autoreleasepool {
        [SWSpoofManager shared];
        InstallSafariHooks();

        // Lệnh 1: Chỉ Wipe (com.custom.safari.wipe)
        int wipeToken = 0;
        notify_register_dispatch("com.custom.safari.wipe", &wipeToken, dispatch_get_main_queue(), ^(int t) {
            PerformSafariDeepWipeAndRotate(YES);
        });

        // Lệnh 2: Chỉ Backup toàn bộ phiên hiện tại (com.custom.safari.backup)
        int backupToken = 0;
        notify_register_dispatch("com.custom.safari.backup", &backupToken, dispatch_get_main_queue(), ^(int t) {
            PerformFullSafariBackup(@"AutoTouch", NO, nil);
        });

        // Lệnh 3: Backup toàn bộ xong tự động Wipe sang máy mới (com.custom.safari.backup_and_wipe)
        int bwToken = 0;
        notify_register_dispatch("com.custom.safari.backup_and_wipe", &bwToken, dispatch_get_main_queue(), ^(int t) {
            PerformFullSafariBackup(@"AutoTouch", YES, nil);
        });

        dispatch_async(dispatch_get_main_queue(), ^{
            [[SWFloatingController shared] tryAttachButton];
            gCheckTimer = [NSTimer scheduledTimerWithTimeInterval:0.5
                                                           target:[SWFloatingController shared]
                                                         selector:@selector(tryAttachButton)
                                                         userInfo:nil
                                                          repeats:YES];
        });

        [[NSNotificationCenter defaultCenter] addObserverForName:UISceneDidActivateNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification *n) {
            [[SWFloatingController shared] tryAttachButton];
        }];
    }
}
