@interface WCPluginsMgr : NSObject
// 这里添加你遇到的 'registerControllerWithTitle:version:controller:' 方法声明
- (void)registerControllerWithTitle:(NSString *)title
                            version:(NSString *)version
                         controller:(NSString *)controller;
@end
