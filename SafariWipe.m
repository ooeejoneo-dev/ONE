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

extern char **environ;

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
@property (nonatomic, assign) BOOL isRecording;
@property (nonatomic, assign) NSUInteger stepCount;
@property (nonatomic, copy) NSString *sessionDir;

+ (instancetype)shared;
- (void)rotateProfile;
- (void)saveProfile;
- (NSString *)buildEnvironmentJS;
- (void)injectIntoUserContentController:(WKUserContentController *)ucc;
- (void)startRecordingSession;
- (NSString *)stopRecordingSession;
- (void)recordStepWithType:(NSString *)type url:(NSString *)url;
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
    return [docDir stringByAppendingPathComponent:@".safari_amzfr_v66.plist"];
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
    if (dict && dict[@"userAgent"] && dict[@"idfv"]) {
        self.userAgent = dict[@"userAgent"];
        self.iosVersion = dict[@"iosVersion"] ?: @"26.0";
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
    } else {
        self.isButtonVisible = YES;
        [self rotateProfile];
    }
}

- (void)saveProfile {
    NSDictionary *dict = @{
        @"userAgent": self.userAgent ?: @"",
        @"iosVersion": self.iosVersion ?: @"26.0",
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
        @"isButtonVisible": @(self.isButtonVisible)
    };
    [dict writeToFile:[self profilePath] atomically:YES];
}

- (void)rotateProfile {
    NSArray<NSArray<NSString *> *> *ios16Profiles = @[
        @[@"16_5",    @"16.5", @"16.5"],
        @[@"16_6",    @"16.6", @"16.6"],
        @[@"16_6_1",  @"16.6", @"16.6.1"],
        @[@"16_7_8",  @"16.6", @"16.7.8"],
        @[@"16_7_10", @"16.6", @"16.7.10"],
        @[@"16_7_16", @"16.6", @"16.7.16"]
    ];

    NSArray<NSArray<NSString *> *> *ios26Profiles = @[
        @[@"18_6",   @"26.0", @"26.0"],
        @[@"18_6",   @"26.1", @"26.1"],
        @[@"18_6",   @"26.2", @"26.2"],
        @[@"26_0",   @"26.0", @"26.0"],
        @[@"26_0_1", @"26.0", @"26.0.1"],
        @[@"26_1",   @"26.1", @"26.1"],
        @[@"26_2",   @"26.2", @"26.2"],
        @[@"26_3",   @"26.3", @"26.3"]
    ];

    BOOL pickIOS26 = (arc4random_uniform(2) == 1);
    NSArray<NSArray<NSString *> *> *pool = pickIOS26 ? ios26Profiles : ios16Profiles;
    NSArray<NSString *> *picked = pool[arc4random_uniform((uint32_t)pool.count)];

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

    [self saveProfile];
}

- (NSString *)buildEnvironmentJS {
    NSTimeZone *parisTZ = [NSTimeZone timeZoneWithName:@"Europe/Paris"];
    NSInteger secondsFromGMT = [parisTZ secondsFromGMTForDate:[NSDate date]];
    NSInteger jsTzOffset = -(secondsFromGMT / 60);

    // Zero-Footprint IIFE: Không gắn bất kỳ biến hay thuộc tính nào lên window hoặc Array
    return [NSString stringWithFormat:
        @"(function() {"
        @"  try {"
        @"    const seed = %ld;"
        @"    const cores = %ld;"
        @"    const tzOffset = %ld;"
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
        @"  } catch (err) {}"
        @"})();",
        (long)self.canvasSeed, (long)self.cpuCores, (long)jsTzOffset];
}

- (void)injectIntoUserContentController:(WKUserContentController *)ucc {
    if (!ucc) return;
    // Kiểm tra ở tầng Objective-C để không bao giờ nạp trùng WKUserScript
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

- (void)startRecordingSession {
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.dateFormat = @"yyyyMMdd_HHmmss";
    NSString *folderName = [NSString stringWithFormat:@"session_%@", [df stringFromDate:[NSDate date]]];
    NSString *baseDir = [[NSHomeDirectory() stringByAppendingPathComponent:@"Documents/FWAmzSteps"] stringByAppendingPathComponent:folderName];
    [[NSFileManager defaultManager] createDirectoryAtPath:baseDir withIntermediateDirectories:YES attributes:nil error:nil];
    self.sessionDir = baseDir;
    self.stepCount = 0;
    self.isRecording = YES;
}

- (NSString *)stopRecordingSession {
    self.isRecording = NO;
    return self.sessionDir ?: @"";
}

- (void)recordStepWithType:(NSString *)type url:(NSString *)url {
    if (!self.isRecording || !self.sessionDir || !url) return;
    self.stepCount++;
    NSUInteger idx = self.stepCount;
    NSString *dir = self.sessionDir;

    [[WKWebsiteDataStore defaultDataStore].httpCookieStore getAllCookies:^(NSArray<NSHTTPCookie *> *cookies) {
        NSMutableDictionary *cookieDict = [NSMutableDictionary dictionary];
        for (NSHTTPCookie *c in cookies) {
            if ([c.domain containsString:@"amazon"]) {
                cookieDict[c.name] = c.value;
            }
        }
        NSDictionary *stepData = @{
            @"step": @(idx),
            @"type": type ?: @"NAV",
            @"url": url,
            @"timestamp": [[NSDate date] description],
            @"cookies_after": cookieDict
        };
        NSData *json = [NSJSONSerialization dataWithJSONObject:stepData options:NSJSONWritingPrettyPrinted error:nil];
        NSString *fileName = [NSString stringWithFormat:@"%03lu_%@.json", (unsigned long)idx, type];
        [json writeToFile:[dir stringByAppendingPathComponent:fileName] atomically:YES];
    }];
}

@end

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
        [[SWSpoofManager shared] injectIntoUserContentController:webView.configuration.userContentController];
        NSString *spoofedUA = [SWSpoofManager shared].userAgent;
        if (spoofedUA.length > 0 && orig_WKWebView_setCustomUA) {
            ((void (*)(id, SEL, NSString *))orig_WKWebView_setCustomUA)(webView, @selector(setCustomUserAgent:), spoofedUA);
        }
    }
    return webView;
}

static void swizzled_WKUCC_removeAllUserScripts(WKUserContentController *self, SEL _cmd) {
    ((void (*)(id, SEL))orig_WKUCC_removeAllUserScripts)(self, _cmd);
    [[SWSpoofManager shared] injectIntoUserContentController:self];
}

static void swizzled_WKWebView_setCustomUA(WKWebView *self, SEL _cmd, NSString *customUserAgent) {
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
    [[SWSpoofManager shared] injectIntoUserContentController:self.configuration.userContentController];
    if ([SWSpoofManager shared].isRecording && request.URL.absoluteString) {
        [[SWSpoofManager shared] recordStepWithType:@"WEB_NAV" url:request.URL.absoluteString];
    }
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
        @"/var/mobile/Library/Caches/com.apple.mobilesafari"
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
                [f containsString:@"History"]) {
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

        WKWebsiteDataStore *dataStore = [WKWebsiteDataStore defaultDataStore];
        WKHTTPCookieStore *wkCookieStore = dataStore.httpCookieStore;
        [wkCookieStore getAllCookies:^(NSArray<NSHTTPCookie *> *wkCookies) {
            dispatch_group_t grp = dispatch_group_create();
            for (NSHTTPCookie *c in wkCookies) {
                dispatch_group_enter(grp);
                [wkCookieStore deleteCookie:c completionHandler:^{
                    dispatch_group_leave(grp);
                }];
            }
            dispatch_group_notify(grp, dispatch_get_main_queue(), ^{
                NSSet *allTypes = [WKWebsiteDataStore allWebsiteDataTypes];
                NSDate *epoch = [NSDate dateWithTimeIntervalSince1970:0];
                [dataStore removeDataOfTypes:allTypes modifiedSince:epoch completionHandler:^{
                    FinalizeHardExit(shouldExitAfterWipe);
                }];
            });
        }];
    });
}

@interface SWFloatingController : NSObject
+ (instancetype)shared;
- (void)tryAttachButton;
- (void)applyButtonAppearance;
- (void)showMainPanel;
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
        BOOL is26 = [[SWSpoofManager shared].iosVersion hasPrefix:@"26"];
        btn.backgroundColor = is26 ? [UIColor colorWithRed:0.10 green:0.32 blue:0.75 alpha:0.92] : [UIColor colorWithRed:0.85 green:0.14 blue:0.18 alpha:0.92];
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

- (void)copyDiagnosticReportWithCookies:(NSArray<NSString *> *)cookiePairs {
    SWSpoofManager *sm = [SWSpoofManager shared];
    CGRect scr = [UIScreen mainScreen].bounds;
    CGFloat scale = [UIScreen mainScreen].scale;
    double memGB = (double)[NSProcessInfo processInfo].physicalMemory / (1024.0 * 1024.0 * 1024.0);

    NSString *cookieBlock = cookiePairs.count > 0 ? [cookiePairs componentsJoinedByString:@"; "] : @"(no cookies)";
    NSString *report = [NSString stringWithFormat:
        @"=== SAFARI V6.6 DIAGNOSTIC (ZERO-FOOTPRINT JS) ===\n"
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
        @"--- COOKIES ---\n"
        @"%@\n",
        [[NSDate date] description],
        sm.idfv, sm.idfa, sm.serial, (long)sm.canvasSeed,
        sm.iosVersion, scr.size.width * scale, scr.size.height * scale, scale, memGB, sm.userAgent,
        sm.localeCode, sm.timeZoneName,
        sm.carrierName, sm.carrierISO, sm.carrierMCC, sm.carrierMNC,
        cookieBlock];

    [UIPasteboard generalPasteboard].string = report;
}

- (void)showMainPanel {
    [[WKWebsiteDataStore defaultDataStore].httpCookieStore getAllCookies:^(NSArray<NSHTTPCookie *> *cookies) {
        NSMutableArray<NSString *> *amzCookies = [NSMutableArray array];
        for (NSHTTPCookie *c in cookies) {
            if ([c.domain containsString:@"amazon"]) {
                [amzCookies addObject:[NSString stringWithFormat:@"%@=%@", c.name, c.value]];
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            SWSpoofManager *sm = [SWSpoofManager shared];
            NSString *recStatus = sm.isRecording ? [NSString stringWithFormat:@"ĐANG GHI (%lu bước)", (unsigned long)sm.stepCount] : @"Đang tắt";
            NSString *msg = [NSString stringWithFormat:
                @"• Nhánh UA: iOS %@ (%ld Cores)\n"
                @"• HW Seed (WebGL/Canvas/Rect): #%ld\n"
                @"• Vùng: %@ | %@\n"
                @"• Nhà mạng: %@ (%@-%@)\n"
                @"• Serial: %@ | Cookie: %lu\n"
                @"• Rec: %@\n"
                @"• IDFV: %@\n\n"
                @"• User-Agent:\n%@",
                sm.iosVersion, (long)sm.cpuCores,
                (long)sm.canvasSeed,
                sm.localeCode, sm.timeZoneName,
                sm.carrierName, sm.carrierMCC, sm.carrierMNC,
                sm.serial, (unsigned long)amzCookies.count,
                recStatus, sm.idfv,
                sm.userAgent];

            UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Safari Spoof V6.6 (Zero-Footprint)"
                                                                           message:msg
                                                                    preferredStyle:UIAlertControllerStyleAlert];

            [alert addAction:[UIAlertAction actionWithTitle:@"Wipe Sạch Tab + Tiến Trình & Đổi Máy" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *a) {
                PerformSafariDeepWipeAndRotate(YES);
            }]];

            [alert addAction:[UIAlertAction actionWithTitle:@"Info: Copy Diagnostic Report" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                [self copyDiagnosticReportWithCookies:amzCookies];
            }]];

            [alert addAction:[UIAlertAction actionWithTitle:[NSString stringWithFormat:@"Cookies: Copy All (%lu)", (unsigned long)amzCookies.count] style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                if (amzCookies.count > 0) {
                    [UIPasteboard generalPasteboard].string = [amzCookies componentsJoinedByString:@"; "];
                }
            }]];

            NSString *recBtnTitle = sm.isRecording ? @"Stop Rec (Lưu vào Documents/FWAmzSteps)" : @"Rec: Bắt đầu ghi StepRecorder";
            [alert addAction:[UIAlertAction actionWithTitle:recBtnTitle style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                if (sm.isRecording) {
                    NSString *savedPath = [sm stopRecordingSession];
                    [UIPasteboard generalPasteboard].string = savedPath;
                } else {
                    [sm startRecordingSession];
                }
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
    }];
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

        int token = 0;
        notify_register_dispatch("com.custom.safari.wipe", &token, dispatch_get_main_queue(), ^(int t) {
            PerformSafariDeepWipeAndRotate(YES);
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
