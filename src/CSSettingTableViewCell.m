#import "CSSettingTableViewCell.h"
#import <objc/runtime.h>

@interface CSSettingItem ()
@property (nonatomic, assign, readwrite) CSSettingItemType itemType;
@end

@implementation CSSettingItem

- (instancetype)initWithType:(CSSettingItemType)type {
    if (self = [super init]) {
        _itemType = type;
        switch (type) {
            case CSSettingItemTypeSwitch:
                _switchValue = NO;
                break;
            case CSSettingItemTypeInput:
                _inputValue = @"";
                _inputPlaceholder = @"";
                break;
            default:
                break;
        }
    }
    return self;
}

- (void)setDetail:(NSString *)detail {
    if (self.itemType == CSSettingItemTypeSwitch) {
        _detail = nil;
    } else {
        _detail = [detail copy];
    }
}

+ (instancetype)itemWithTitle:(NSString *)title
                    iconName:(NSString *)iconName
                  iconColor:(UIColor *)iconColor
                     detail:(nullable NSString *)detail {
    CSSettingItem *item = [[CSSettingItem alloc] init];
    item.title = title;
    item.iconName = iconName;
    item.iconColor = iconColor;
    item.detail = detail;
    item.itemType = CSSettingItemTypeNormal;
    return item;
}

+ (instancetype)switchItemWithTitle:(NSString *)title
                          iconName:(NSString *)iconName
                         iconColor:(UIColor *)iconColor
                        switchValue:(BOOL)switchValue
                   valueChangedBlock:(nullable void(^)(BOOL isOn))valueChanged {
    CSSettingItem *item = [[CSSettingItem alloc] init];
    item.title = title;
    item.iconName = iconName;
    item.iconColor = iconColor;
    item.itemType = CSSettingItemTypeSwitch;
    item.switchValue = switchValue;
    item.switchValueChanged = valueChanged;
    item.detail = nil;
    return item;
}

+ (instancetype)inputItemWithTitle:(NSString *)title
                         iconName:(NSString *)iconName
                        iconColor:(UIColor *)iconColor
                        inputValue:(nullable NSString *)inputValue
                    inputPlaceholder:(nullable NSString *)placeholder
                   valueChangedBlock:(nullable void(^)(NSString *value))valueChanged {
    CSSettingItem *item = [[CSSettingItem alloc] init];
    item.title = title;
    item.iconName = iconName;
    item.iconColor = iconColor;
    item.itemType = CSSettingItemTypeInput;
    item.inputValue = inputValue;
    item.inputPlaceholder = placeholder;
    item.inputValueChanged = valueChanged;
    item.detail = inputValue;
    return item;
}

@end

@implementation CSSettingSection

+ (instancetype)sectionWithHeader:(NSString *)header items:(NSArray<CSSettingItem *> *)items {
    CSSettingSection *section = [[CSSettingSection alloc] init];
    section.header = header;
    section.items = items;
    return section;
}

@end

@interface CSSettingTableViewCell ()
@property (nonatomic, strong) CSSettingItem *currentItem;
@end

@implementation CSSettingTableViewCell

+ (NSString *)reuseIdentifier {
    return @"CSSettingTableViewCell";
}

+ (void)registerToTableView:(UITableView *)tableView {
    [tableView registerClass:self forCellReuseIdentifier:[self reuseIdentifier]];
}

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier {
    if (self = [super initWithStyle:UITableViewCellStyleValue1 reuseIdentifier:reuseIdentifier]) {
        [self setupUI];
    }
    return self;
}

- (void)setupUI {
    UIView *selectedBackgroundView = [[UIView alloc] init];
    selectedBackgroundView.backgroundColor = [UIColor tertiarySystemGroupedBackgroundColor];
    self.selectedBackgroundView = selectedBackgroundView;
    self.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    
    self.imageView.contentMode = UIViewContentModeCenter;
    self.imageView.translatesAutoresizingMaskIntoConstraints = NO;
    
    [NSLayoutConstraint activateConstraints:@[
        [self.imageView.centerYAnchor constraintEqualToAnchor:self.contentView.centerYAnchor],
        [self.imageView.leadingAnchor constraintEqualToAnchor:self.contentView.leadingAnchor constant:15.0f],
        [self.imageView.widthAnchor constraintEqualToConstant:29.0f],
        [self.imageView.heightAnchor constraintEqualToConstant:29.0f]
    ]];
}

- (void)prepareForReuse {
    [super prepareForReuse];
    self.textLabel.text = nil;
    self.detailTextLabel.text = nil;
    self.imageView.image = nil;
    self.imageView.tintColor = nil;
    self.accessoryType = UITableViewCellAccessoryNone;
    self.accessoryView = nil;
    self.currentItem = nil;
}

- (void)configureWithItem:(CSSettingItem *)item {
    if (!item) return;
    
    self.currentItem = item;
    self.textLabel.text = item.title;
    
    if (item.iconName.length > 0) {
        self.imageView.image = [UIImage systemImageNamed:item.iconName];
        self.imageView.tintColor = item.iconColor ?: [UIColor labelColor];
    } else {
        self.imageView.image = nil;
    }
    
    switch (item.itemType) {
        case CSSettingItemTypeSwitch:
            [self configureSwitchItem:item];
            break;
        case CSSettingItemTypeInput:
            [self configureInputItem:item];
            break;
        case CSSettingItemTypeNormal:
            [self configureNormalItem:item];
            break;
    }
}

- (void)configureSwitchItem:(CSSettingItem *)item {
    UISwitch *switchView = [[UISwitch alloc] init];
    switchView.on = item.switchValue;
    [switchView addTarget:self action:@selector(switchValueChanged:) forControlEvents:UIControlEventValueChanged];
    
    [self.contentView addSubview:switchView];
    switchView.translatesAutoresizingMaskIntoConstraints = NO;
    
    [NSLayoutConstraint activateConstraints:@[
        [switchView.centerYAnchor constraintEqualToAnchor:self.contentView.centerYAnchor],
        [switchView.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-15.0f]
    ]];
    
    self.detailTextLabel.text = nil;
    self.accessoryView = nil;
    self.accessoryType = UITableViewCellAccessoryNone;
    self.selectionStyle = UITableViewCellSelectionStyleNone;
}

- (void)configureInputItem:(CSSettingItem *)item {
    self.detailTextLabel.text = item.detail ?: item.inputValue;
    self.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    self.selectionStyle = UITableViewCellSelectionStyleDefault;
}

- (void)configureNormalItem:(CSSettingItem *)item {
    self.detailTextLabel.text = item.detail;
    self.accessoryType = UITableViewCellAccessoryNone;
    self.selectionStyle = UITableViewCellSelectionStyleDefault;
}

- (void)switchValueChanged:(UISwitch *)sender {
    if (self.currentItem.switchValueChanged) {
        self.currentItem.switchValue = sender.on;
        self.currentItem.switchValueChanged(sender.on);
    }
}

- (void)layoutSubviews {
    [super layoutSubviews];
    
    CGFloat fixedLabelX = 54.0f;
    CGFloat spacing = 10.0f;
    CGFloat rightMargin = 15.0f;
    
    CGRect textLabelFrame = self.textLabel.frame;
    textLabelFrame.origin.x = fixedLabelX;
    self.textLabel.frame = textLabelFrame;
    
    if (self.detailTextLabel.text.length > 0) {
        CGRect detailFrame = self.detailTextLabel.frame;
        CGFloat titleWidth = [self.textLabel sizeThatFits:CGSizeMake(CGFLOAT_MAX, textLabelFrame.size.height)].width;
        CGFloat fixedDetailX = fixedLabelX + 80.0f;
        
        if (fixedDetailX > fixedLabelX + titleWidth + spacing) {
            detailFrame.origin.x = fixedDetailX;
        } else {
            detailFrame.origin.x = fixedLabelX + titleWidth + spacing;
        }
        
        self.detailTextLabel.frame = detailFrame;
    }
}

@end

@implementation CSUIHelper

+ (void)showInputAlertWithTitle:(NSString *)title
                        message:(nullable NSString *)message
                       initialValue:(nullable NSString *)initialValue
                       placeholder:(nullable NSString *)placeholder
                      inViewController:(UIViewController *)viewController
                      completion:(void(^)(NSString *value))completion {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title
                                                                   message:message
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    
    [alert addAction:[UIAlertAction actionWithTitle:@"确定" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
        UITextField *textField = alert.textFields.firstObject;
        NSString *text = textField.text;
        if (completion) {
            completion(text ?: @"");
        }
    }]];
    
    [alert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = placeholder ?: @"请输入";
        textField.text = initialValue ?: @"";
        textField.clearButtonMode = UITextFieldViewModeWhileEditing;
        textField.keyboardType = UIKeyboardTypeDefault;
    }];
    
    [viewController presentViewController:alert animated:YES completion:nil];
}

@end
