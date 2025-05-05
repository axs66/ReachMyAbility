#import <Preferences/PSViewController.h>
#import <Foundation/Foundation.h>
#import "NSBundle+RMAPrefs.h"
#import "RMAUserDefaults.h"

@interface RMARootListController : PSViewController <UITableViewDelegate, UITableViewDataSource> 
@property (nonatomic, strong) UITableView *tableView;
@end

@interface UISwitchVisualElement : UIView
@property (nonatomic, assign) BOOL showsOnOffLabel;
@end

@interface UISwitch (Private)
@property (nonatomic, strong) UISwitchVisualElement *visualElement;
@end

@interface UISlider (Private)
- (void)setShowValue:(BOOL)showValue;
@end
