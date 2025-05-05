#import <UIKit/UIKit.h>
#import "Preferences.h"  // 确保导入了所需的框架和类
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import "CSInputTextSettingsViewController.h"
#import "CSEntrySettingsViewController.h"
#import "CSCustomViewController.h"
#import "WCPluginsHeader.h"

%hook MoreViewController

- (void)addFunctionSection {
    %orig;
    
    // 获取入口显示模式
    CSEntryDisplayMode displayMode = getEntryDisplayMode();
    if (displayMode == CSEntryDisplayModePlugin) return;
    
    // 获取自定义入口标题
    NSString *entryTitle = getCustomEntryTitle();
    
    // 创建一个自定义按钮，作为新的入口
    UIButton *customEntryButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [customEntryButton setTitle:entryTitle forState:UIControlStateNormal];
    [customEntryButton addTarget:self action:@selector(onCustomEntryClick) forControlEvents:UIControlEventTouchUpInside];
    
    // 将自定义按钮添加到视图
    customEntryButton.frame = CGRectMake(20, 100, 200, 44); // 你可以调整按钮的位置和大小
    [self.view addSubview:customEntryButton];
}

- (void)onCustomEntryClick {
    // 处理自定义入口点击事件
    NSLog(@"[WeChatTweak] 自定义入口被点击");
    // 在这里你可以执行跳转或其他逻辑
    [self performSelector:@selector(presentCustomViewController)];
}

- (void)presentCustomViewController {
    // 展示自定义视图控制器
    UIViewController *customVC = [[NSClassFromString(@"CSCustomViewController") alloc] init];
    UINavigationController *navVC = [[UINavigationController alloc] initWithRootViewController:customVC];
    [self presentViewController:navVC animated:YES completion:nil];
}

%end

%hook CSEntrySettingsViewController

- (void)viewDidLoad {
    %orig;
    
    // 如果已经注册过，则不再重复注册
    CSEntryDisplayMode displayMode = getEntryDisplayMode();
    if (displayMode == CSEntryDisplayModeMore) return;
    
    if (NSClassFromString(@"WCPluginsMgr") && isRegister == 0) {
        isRegister = 1;
        NSString *title = getCustomEntryTitle();
        NSString *version = @"1.0";
        NSString *controller = @"CSCustomViewController";
        
        @try {
            Class wcPluginsMgr = objc_getClass("WCPluginsMgr");
            if (wcPluginsMgr) {
                id instance = [wcPluginsMgr performSelector:@selector(sharedInstance)];
                if (instance && [instance respondsToSelector:@selector(registerControllerWithTitle:version:controller:)]) {
                    [instance registerControllerWithTitle:title version:version controller:controller];
                }
            }
        } @catch (NSException *exception) {
            NSLog(@"[WeChatTweak] 注册入口失败: %@", exception);
        }
    }
}

%end

%hook CSEntryDisplayViewController

- (void)viewDidLoad {
    %orig;
    
    // 设置按钮，处理点击操作
    UIButton *moreEntryButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [moreEntryButton setTitle:@"更多入口" forState:UIControlStateNormal];
    [moreEntryButton addTarget:self action:@selector(onMoreEntryClick) forControlEvents:UIControlEventTouchUpInside];
    
    // 将按钮添加到视图
    moreEntryButton.frame = CGRectMake(20, 200, 200, 44);
    [self.view addSubview:moreEntryButton];
}

- (void)onMoreEntryClick {
    // 跳转到更多设置页面
    MoreViewController *moreVC = [[MoreViewController alloc] init];
    [self.navigationController pushViewController:moreVC animated:YES];
}

%end

// 处理消息框中的按钮操作（比如“发送”按钮）
%hook BaseMsgContentViewController

- (void)viewDidLoad {
    %orig;
    
    // 检查是否需要添加自定义按钮
    if (![self isCustomEntryAdded]) {
        [self addCustomEntryButton];
    }
}

- (BOOL)isCustomEntryAdded {
    // 检查是否已添加自定义入口
    return _customEntryAdded;
}

- (void)addCustomEntryButton {
    UIButton *customButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [customButton setTitle:@"自定义入口" forState:UIControlStateNormal];
    [customButton addTarget:self action:@selector(onCustomButtonClick) forControlEvents:UIControlEventTouchUpInside];
    customButton.frame = CGRectMake(20, 300, 200, 44); // 根据需求调整位置和大小
    [self.view addSubview:customButton];
    _customEntryAdded = YES;
}

- (void)onCustomButtonClick {
    // 自定义按钮点击处理
    NSLog(@"[WeChatTweak] 自定义按钮点击");
    // 跳转到目标视图或执行其他操作
}

%end
