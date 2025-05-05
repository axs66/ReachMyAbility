#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface RMAUserDefaults : NSUserDefaults 

@property (class, readonly, strong) RMAUserDefaults *standardUserDefaults;

- (void)reset;
+ (void)resetUserDefaults;

@end

NS_ASSUME_NONNULL_END
