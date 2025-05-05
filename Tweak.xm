#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import "CSInputTextSettingsViewController.h"
#import "CSEntrySettingsViewController.h"
#import "CSCustomViewController.h"
#import "WCPluginsHeader.h"

// 输入框设置相关常量
static NSString * const kInputTextEnabledKey = @"com.wechat.enhance.inputText.enabled";
static NSString * const kInputTextContentKey = @"com.wechat.enhance.inputText.content";
static NSString * const kInputTextColorKey = @"com.wechat.enhance.inputText.color";
static NSString * const kInputTextAlphaKey = @"com.wechat.enhance.inputText.alpha";
static NSString * const kInputTextFontSizeKey = @"com.wechat.enhance.inputText.fontSize";
static NSString * const kInputTextBoldKey = @"com.wechat.enhance.inputText.bold";
static NSString * const kInputTextRoundedCornersKey = @"com.wechat.enhance.inputText.roundedCorners";
static NSString * const kInputTextCornerRadiusKey = @"com.wechat.enhance.inputText.cornerRadius";
static NSString * const kInputTextBorderEnabledKey = @"com.wechat.enhance.inputText.border.enabled";
static NSString * const kInputTextBorderWidthKey = @"com.wechat.enhance.inputText.border.width";
static NSString * const kInputTextBorderColorKey = @"com.wechat.enhance.inputText.border.color";

// 入口设置相关常量
static NSString * const kEntryDisplayModeKey = @"com.wechat.tweak.entry.display.mode";
static NSString * const kEntryCustomTitleKey = @"com.wechat.tweak.entry.custom.title";
static NSString * const kEntrySettingsChangedNotification = @"com.wechat.tweak.entry.settings.changed";

// 默认值
static NSString * const kDefaultInputText = @"我爱你呀";
static CGFloat const kDefaultFontSize = 15.0f;
static CGFloat const kDefaultTextAlpha = 0.5f;
static CGFloat const kDefaultCornerRadius = 18.0f;
static CGFloat const kDefaultBorderWidth = 1.0f;

// 全局变量
static NSString *gCustomEntryTitle = nil;
static BOOL isInChatView = NO;

// 类声明
@interface BaseMsgContentViewController : UIViewController
- (id)GetContact;
@end

@interface MMGrowTextView : UIView
@property(nonatomic) __weak NSString *placeHolder;
@property(nonatomic) __weak NSAttributedString *attributePlaceholder;
- (void)setPlaceHolderColor:(UIColor *)color;
- (void)setPlaceHolderMultiLine:(BOOL)multiLine;
@end

@interface MMInputToolView : UIView
@property(retain, nonatomic) MMGrowTextView *textView;
@end

// 输入框功能实现
static BOOL isInputTextEnabled() {
    return [[NSUserDefaults standardUserDefaults] boolForKey:kInputTextEnabledKey];
}

static BOOL isInputTextRoundedCornersEnabled() {
    return [[NSUserDefaults standardUserDefaults] boolForKey:kInputTextRoundedCornersKey];
}

static BOOL isInputTextBorderEnabled() {
    return [[NSUserDefaults standardUserDefaults] boolForKey:kInputTextBorderEnabledKey];
}

static BOOL shouldApplyInputTextStyle() {
    return isInChatView && isInputTextEnabled();
}

static BOOL shouldApplyRoundedCorners() {
    return isInChatView && isInputTextRoundedCornersEnabled();
}

static BOOL shouldApplyBorder() {
    return isInChatView && isInputTextBorderEnabled();
}

static CGFloat getCornerRadius() {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    CGFloat cornerRadius = [defaults floatForKey:kInputTextCornerRadiusKey];
    return cornerRadius > 0 ? cornerRadius : kDefaultCornerRadius;
}

static CGFloat getBorderWidth() {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    CGFloat borderWidth = [defaults floatForKey:kInputTextBorderWidthKey];
    return borderWidth > 0 ? borderWidth : kDefaultBorderWidth;
}

static UIColor *getBorderColorFromDefaults() {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSData *colorData = [defaults objectForKey:kInputTextBorderColorKey];
    if (colorData) {
        NSError *error = nil;
        UIColor *savedColor = [NSKeyedUnarchiver unarchivedObjectOfClass:[UIColor class] fromData:colorData error:&error];
        if (savedColor && !error) return savedColor;
    }
    return [UIColor systemGrayColor];
}

static NSString *getInputTextContent() {
    NSString *savedText = [[NSUserDefaults standardUserDefaults] objectForKey:kInputTextContentKey];
    return savedText.length > 0 ? savedText : kDefaultInputText;
}

static UIColor *getTextColorFromDefaults() {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSData *colorData = [defaults objectForKey:kInputTextColorKey];
    if (colorData) {
        NSError *error = nil;
        UIColor *savedColor = [NSKeyedUnarchiver unarchivedObjectOfClass:[UIColor class] fromData:colorData error:&error];
        if (savedColor && !error) {
            CGFloat alpha = [defaults floatForKey:kInputTextAlphaKey];
            if (alpha == 0 && ![defaults objectForKey:kInputTextAlphaKey]) {
                alpha = kDefaultTextAlpha;
            }
            return [savedColor colorWithAlphaComponent:alpha];
        }
    }
    CGFloat alpha = [defaults floatForKey:kInputTextAlphaKey];
    if (alpha == 0 && ![defaults objectForKey:kInputTextAlphaKey]) {
        alpha = kDefaultTextAlpha;
    }
    return [UIColor colorWithWhite:0.5 alpha:alpha];
}

static void applyRoundedCornersIfNeeded(MMGrowTextView *textView) {
    BOOL shouldApplyCorners = shouldApplyRoundedCorners();
    BOOL shouldApplyBorderStyle = shouldApplyBorder();
    
    if (!shouldApplyCorners && !shouldApplyBorderStyle) {
        textView.layer.cornerRadius = 0;
        textView.layer.borderWidth = 0;
        textView.clipsToBounds = NO;
        return;
    }
    
    CGFloat cornerRadius = shouldApplyCorners ? getCornerRadius() : 0;
    CGFloat borderWidth = shouldApplyBorderStyle ? getBorderWidth() : 0;
    UIColor *borderColor = shouldApplyBorderStyle ? getBorderColorFromDefaults() : [UIColor clearColor];
    
    textView.layer.cornerRadius = cornerRadius;
    textView.layer.borderWidth = borderWidth;
    textView.layer.borderColor = borderColor.CGColor;
    textView.clipsToBounds = (cornerRadius > 0);
}

static void applyPlaceHolderSettings(MMGrowTextView *textView) {
    if (!shouldApplyInputTextStyle()) {
        if (shouldApplyRoundedCorners() || shouldApplyBorder()) {
            applyRoundedCornersIfNeeded(textView);
        }
        return;
    }
    
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSString *customText = getInputTextContent();
    CGFloat fontSize = [defaults floatForKey:kInputTextFontSizeKey];
    if (fontSize <= 0) fontSize = kDefaultFontSize;
    BOOL isBold = [defaults boolForKey:kInputTextBoldKey];
    
    UIColor *textColor = getTextColorFromDefaults();
    [textView setPlaceHolderColor:textColor];
    [textView setPlaceHolderMultiLine:YES];
    
    UIFont *font = isBold ? 
        [UIFont boldSystemFontOfSize:fontSize] : 
        [UIFont systemFontOfSize:fontSize];
    
    NSMutableParagraphStyle *paragraphStyle = [[NSMutableParagraphStyle alloc] init];
    paragraphStyle.alignment = NSTextAlignmentLeft;
    
    NSDictionary *attributes = @{
        NSFontAttributeName: font,
        NSForegroundColorAttributeName: textColor,
        NSParagraphStyleAttributeName: paragraphStyle
    };
    
    NSAttributedString *attributedPlaceholder = [[NSAttributedString alloc] 
                                               initWithString:customText 
                                               attributes:attributes];
    
    textView.attributePlaceholder = attributedPlaceholder;
    textView.placeHolder = customText;
    
    applyRoundedCornersIfNeeded(textView);
}

// 入口功能实现
static inline UIImage * __nullable getCustomEntryIcon(void) {
    UIImage *icon = [UIImage systemImageNamed:@"signature.th"];
    return [icon imageWithTintColor:[UIColor systemBlueColor] renderingMode:UIImageRenderingModeAlwaysOriginal];
}

static CSEntryDisplayMode getEntryDisplayMode() {
    return (CSEntryDisplayMode)[[NSUserDefaults standardUserDefaults] integerForKey:kEntryDisplayModeKey];
}

static NSString *getCustomEntryTitle() {
    if (!gCustomEntryTitle) {
        NSString *savedTitle = [[NSUserDefaults standardUserDefaults] objectForKey:kEntryCustomTitleKey];
        gCustomEntryTitle = savedTitle ?: @"Wechat";
    }
    return gCustomEntryTitle;
}

static void loadEntrySettings() {
    gCustomEntryTitle = getCustomEntryTitle();
    NSLog(@"[WeChatTweak] 入口设置已加载: 显示模式=%ld, 标题=%@", (long)getEntryDisplayMode(), gCustomEntryTitle);
}

static void entrySettingsChangedCallback(CFNotificationCenterRef center, void *observer, CFStringRef name, const void *object, CFDictionaryRef userInfo) {
    loadEntrySettings();
}

// Hook 实现
%hook BaseMsgContentViewController

- (void)viewDidLoad {
    %orig;
    isInChatView = YES;
}

- (void)viewWillAppear:(BOOL)animated {
    %orig;
    isInChatView = YES;
}

- (void)viewWillDisappear:(BOOL)animated {
    %orig;
    isInChatView = NO;
}

%end

%hook MMGrowTextView

- (id)init {
    id view = %orig;
    if (view) applyPlaceHolderSettings(self);
    return view;
}

- (void)layoutSubviews {
    %orig;
    if (shouldApplyRoundedCorners()) {
        applyRoundedCornersIfNeeded(self);
    }
}

%end

%hook MMInputToolView

- (void)layoutSubviews {
    %orig;
    if (self.textView) {
        if (shouldApplyInputTextStyle()) {
            applyPlaceHolderSettings(self.textView);
        } else if (shouldApplyRoundedCorners() || shouldApplyBorder()) {
            applyRoundedCornersIfNeeded(self.textView);
        }
    }
}

%end

%hook MoreViewController

- (void)addFunctionSection {
    %orig;
    CSEntryDisplayMode displayMode = getEntryDisplayMode();
    if (displayMode == CSEntryDisplayModePlugin) return;
    
    NSString *entryTitle = getCustomEntryTitle();
    WCTableViewManager *tableViewMgr = MSHookIvar<id>(self, "m_tableViewMgr");
    if (!tableViewMgr) return;
    
    WCTableViewSectionManager *section = [tableViewMgr getSectionAt:2];
    if (!section) return;
    
    WCTableViewCellManager *customEntryCell = [%c(WCTableViewCellManager) normalCellForSel:@selector(onCustomEntryClick)
                                                                          target:self
                                                                       leftImage:getCustomEntryIcon()
                                                                          title:entryTitle
                                                                          badge:nil
                                                                     rightValue:nil
                                                                    rightImage:nil
                                                               withRightRedDot:NO
                                                                      selected:NO];
    
    [section addCell:customEntryCell];
}

%new
- (void)onCustomEntryClick {
    CSCustomViewController *customVC = [[CSCustomViewController alloc] init];
    customVC.title = getCustomEntryTitle();
    UINavigationController *navVC = [[UINavigationController alloc] initWithRootViewController:customVC];
    
    if (@available(iOS 13.0, *)) {
        navVC.modalPresentationStyle = UIModalPresentationFormSheet;
    } else {
        navVC.modalPresentationStyle = UIModalPresentationPageSheet;
    }
    
    [self presentViewController:navVC animated:YES completion:nil];
}

%end

%hook MinimizeViewController

static int isRegister = 0;

-(void)viewDidLoad{
    %orig;
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

%ctor {
    loadEntrySettings();
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
                                   NULL,
                                   entrySettingsChangedCallback,
                                   CFSTR("com.wechat.tweak.entry.settings.changed"),
                                   NULL,
                                   CFNotificationSuspensionBehaviorDeliverImmediately);
}
