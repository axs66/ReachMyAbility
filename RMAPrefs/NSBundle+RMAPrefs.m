#import "NSBundle+RMAPrefs.h"

@implementation NSBundle (ReachMyAbility)

+ (NSBundle *)rma_defaultBundle {
    static NSBundle *bundle = nil;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        NSString *tweakBundlePath = [[NSBundle mainBundle] pathForResource:@"RMAPrefs" ofType:@"bundle"];
        NSString *rootlessBundlePath = jbroot(@"/Library/Application Support/RMAPrefs.bundle");

        bundle = [NSBundle bundleWithPath:tweakBundlePath ?: rootlessBundlePath];
    });

    return bundle;
}

@end