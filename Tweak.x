#import <UIKit/UIKit.h>
#import "RMAPrefs/RMAUserDefaults.h"

@interface SBReachabilityManager : NSObject
@property (nonatomic, assign, readonly) BOOL reachabilityModeActive;

+ (instancetype)sharedInstance;
@end

%hook SBReachabilitySettings
- (CGFloat)reachabilityDefaultKeepAlive {
    if ([[RMAUserDefaults standardUserDefaults] boolForKey:@"enabled"]) {
        CGFloat result = [[RMAUserDefaults standardUserDefaults] floatForKey:@"keepAlive"];
        return result == 301 ? CGFLOAT_MAX : result;
    }

    return %orig;
}
%end

%hook SBReachabilityManager
- (CGFloat)reachabilityYOffset {
    if ([[RMAUserDefaults standardUserDefaults] boolForKey:@"enabled"]) {
        return [[RMAUserDefaults standardUserDefaults] floatForKey:@"downHeight"] ?: %orig;
    }

    return %orig;
}

- (void)deactivateReachability {
    if (![[RMAUserDefaults standardUserDefaults] boolForKey:@"enabled"]) {
        return %orig;
    }

    if (![[RMAUserDefaults standardUserDefaults] boolForKey:@"deactivation"]) {
        %orig;
    }
}

- (void)_screenDidDim {
    if (![[RMAUserDefaults standardUserDefaults] boolForKey:@"enabled"]) {
        return %orig;
    }

    if (![[RMAUserDefaults standardUserDefaults] boolForKey:@"keepOnDim"]) {
        %orig;
    }
}
%end