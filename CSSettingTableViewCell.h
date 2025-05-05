#import <UIKit/UIKit.h>

typedef NS_ENUM(NSInteger, CSSettingItemType) {
    CSSettingItemTypeSwitch,
    CSSettingItemTypeInput,
    CSSettingItemTypeNormal
};

@interface CSSettingItem : NSObject

@property (nonatomic, copy) NSString *title;
@property (nonatomic, copy) NSString *iconName;
@property (nonatomic, strong) UIColor *iconColor;
@property (nonatomic, copy) NSString *detail;
@property (nonatomic, assign) CSSettingItemType type;
@property (nonatomic, copy) void (^valueChangedBlock)(id value);
@property (nonatomic, assign) BOOL switchValue;
@property (nonatomic, copy) NSString *inputValue;
@property (nonatomic, copy) NSString *inputPlaceholder;

+ (instancetype)switchItemWithTitle:(NSString *)title 
                          iconName:(NSString *)iconName 
                         iconColor:(UIColor *)iconColor
                       switchValue:(BOOL)switchValue
                 valueChangedBlock:(void (^)(BOOL isOn))block;

+ (instancetype)inputItemWithTitle:(NSString *)title 
                         iconName:(NSString *)iconName 
                        iconColor:(UIColor *)iconColor
                        inputValue:(NSString *)inputValue
                    inputPlaceholder:(NSString *)placeholder
                   valueChangedBlock:(void (^)(NSString *value))block;

+ (instancetype)itemWithTitle:(NSString *)title 
                    iconName:(NSString *)iconName 
                   iconColor:(UIColor *)iconColor
                     detail:(NSString *)detail;

@end

@interface CSSettingSection : NSObject

@property (nonatomic, copy) NSString *header;
@property (nonatomic, strong) NSArray<CSSettingItem *> *items;

+ (instancetype)sectionWithHeader:(NSString *)header items:(NSArray<CSSettingItem *> *)items;

@end

@interface CSSettingTableViewCell : UITableViewCell

+ (NSString *)reuseIdentifier;
+ (void)registerToTableView:(UITableView *)tableView;
- (void)configureWithItem:(CSSettingItem *)item;

@end
