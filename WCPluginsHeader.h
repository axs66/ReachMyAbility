// WCPluginsHeader.h

// 已有声明
@class WCPluginsMgr;

// 添加以下声明解决编译错误
@interface WCTableViewManager : NSObject
- (id)getSectionAt:(NSInteger)index;
@end

@interface WCTableViewSectionManager : NSObject
- (void)addCell:(id)cell;
@end

@interface WCTableViewCellManager : NSObject
+ (instancetype)normalCellForSel:(SEL)sel
                          target:(id)target
                       leftImage:(UIImage *)leftImage
                           title:(NSString *)title
                           badge:(id)badge
                      rightValue:(id)rightValue
                      rightImage:(UIImage *)rightImage
                withRightRedDot:(BOOL)redDot
                        selected:(BOOL)selected;
@end

@interface MoreViewController : UIViewController
@end
