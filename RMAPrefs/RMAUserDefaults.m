#import "RMAUserDefaults.h"

@implementation RMAUserDefaults

static NSString *const kDefaultsSuiteName = @"com.dvntm.rma";

+ (RMAUserDefaults *)standardUserDefaults {
    static dispatch_once_t onceToken;
    static RMAUserDefaults *defaults = nil;

    dispatch_once(&onceToken, ^{
        defaults = [[self alloc] initWithSuiteName:kDefaultsSuiteName];
        [defaults registerDefaults];
    });

    return defaults;
}

- (void)reset {
    [self removePersistentDomainForName:kDefaultsSuiteName];
}

- (void)registerDefaults {
    CGFloat origHeight = roundf([UIScreen mainScreen].bounds.size.height * 0.4);

    [self registerDefaults:@{
        @"enabled": @YES,
        @"keepAlive": @8,
        @"downHeight": @(origHeight)
    }];
}

+ (void)resetUserDefaults {
    [[self standardUserDefaults] reset];
}

@end
