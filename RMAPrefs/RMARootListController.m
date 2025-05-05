#import "RMARootListController.h"

#define LOC(key) [NSBundle.rma_defaultBundle localizedStringForKey:key value:nil table:nil]

#define TAG_FOR_INDEX_PATH(section, row) ((section << 16) | (row & 0xFFFF))
#define SECTION_FROM_TAG(tag) (tag >> 16)
#define ROW_FROM_TAG(tag) (tag & 0xFFFF)

@implementation RMARootListController
{
    NSArray *_sections;
    NSArray *_main;
    NSArray *_keepalive;
    NSArray *_int;
    NSArray *_height;
    NSArray *_reset;
    NSArray *_developer;
}

- (instancetype)init {

    self = [super init];

    if (self) {
        CGFloat allowedScreenHeight = [UIScreen mainScreen].bounds.size.height * 0.75;

        _main = @[
            @{@"title": @"Enabled", @"icon": @"power", @"type": @"bool", @"key": @"enabled", @"id": @"mainCell"},
            @{@"title": @"Deactivation", @"icon": @"hand.point.up.left", @"type": @"bool", @"key": @"deactivation", @"id": @"mainCell"},
            @{@"title": @"KeepOnDimmedScreen", @"icon": @"sun.dust", @"type": @"bool", @"key": @"keepOnDim", @"id": @"mainCell"},
        ];

        _keepalive = @[
            @{@"type": @"slider", @"min": @0.5, @"max": @301, @"divider": @1, @"key": @"keepAlive", @"id": @"keepaliveCell", @"style": @(UITableViewCellStyleValue1)}
        ];

        _height = @[
            @{@"type": @"slider", @"min": @100, @"max": @(allowedScreenHeight), @"divider": @1, @"key": @"downHeight", @"id": @"heightCell", @"style": @(UITableViewCellStyleValue1)}
        ];

        _reset = @[
            @{@"title": @"ResetSettings", @"icon": @"trash", @"type": @"reset", @"key": @"reset", @"id": @"resetCell"},
        ];

        _developer = @[
            @{@"title": @"FollowX", @"icon": @"newspaper", @"type": @"link", @"key": @"https://x.com/dayanch96", @"id": @"devCell"},
            @{@"title": @"SourceCode", @"icon": @"barcode.viewfinder", @"type": @"link", @"key": @"https://github.com/dayanch96/ReachMyAbility", @"id": @"devCell"},
            @{@"title": @"SupportPatreon", @"icon": @"heart.circle", @"type": @"link", @"key": @"https://patreon.com/dayanch96", @"id": @"devCell"}
        ];

        _sections = @[_main, _keepalive, _height, _reset, _developer];
    }

    return self;
}

- (NSString *)title {
    return @"ReachMyAbility";
}

- (void)viewDidLoad {
    [super viewDidLoad];

    self.tableView = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStyleInsetGrouped];
    self.tableView.translatesAutoresizingMaskIntoConstraints = NO;
    self.tableView.dataSource = self;
    self.tableView.delegate = self;
    self.tableView.tintColor = [UIColor colorWithRed:0.75 green:0.50 blue:0.90 alpha:1.0];

    [self.view addSubview:self.tableView];

    [NSLayoutConstraint activateConstraints:@[
        [self.tableView.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.tableView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
        [self.tableView.widthAnchor constraintEqualToAnchor:self.view.widthAnchor],
        [self.tableView.heightAnchor constraintEqualToAnchor:self.view.heightAnchor]
    ]];
}

- (CGFloat)tableView:(UITableView *)tableView heightForRowAtIndexPath:(NSIndexPath *)indexPath {
    return UITableViewAutomaticDimension;
}

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return _sections.count;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return [_sections[section] count];
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    NSString *header;
    if (section == [_sections indexOfObject:_keepalive]) {
        header = @"KeepAliveDuration";
    }

    if (section == [_sections indexOfObject:_height]) {
        header = @"Height";
    }

    return LOC(header);
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    UITableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:@"cell"];

    if (cell == nil) {
        cell = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:@"cell"];
    }

    if (_sections[indexPath.section]) {
        NSDictionary *data = _sections[indexPath.section][indexPath.row];

        cell = [[UITableViewCell alloc] initWithStyle:[data[@"style"] integerValue] ?: UITableViewCellStyleSubtitle reuseIdentifier:data[@"id"]];

        if (data[@"title"]) {
            cell.textLabel.text = LOC(data[@"title"]);
            cell.textLabel.numberOfLines = 0;
        }

        if (data[@"icon"]) {
            cell.imageView.image = [UIImage systemImageNamed:data[@"icon"]];
        }

        if ([data[@"type"] isEqualToString:@"bool"]) {
            UISwitch *switchControl = [self switchForKey:data[@"key"]];
            switchControl.tag = TAG_FOR_INDEX_PATH(indexPath.section, indexPath.row);

            cell.accessoryView = switchControl;
        }

        if ([data[@"type"] isEqualToString:@"slider"]) {
            UISlider *slider = [self sliderWithKey:data[@"key"] min:[data[@"min"] floatValue] max:[data[@"max"] floatValue]];
            slider.tag = TAG_FOR_INDEX_PATH(indexPath.section, indexPath.row);

            cell.detailTextLabel.text = [self valueStringForKey:data[@"key"] value:slider.value];

            [cell.contentView addSubview:slider];

            [slider.leadingAnchor constraintEqualToAnchor:cell.contentView.layoutMarginsGuide.leadingAnchor constant:5.0].active = YES;
            [slider.trailingAnchor constraintEqualToAnchor:cell.contentView.layoutMarginsGuide.trailingAnchor constant:-50.0].active = YES;
            [slider.centerYAnchor constraintEqualToAnchor:cell.contentView.layoutMarginsGuide.centerYAnchor].active = YES;
        }

        if ([data[@"type"] isEqualToString:@"reset"]) {
            cell.tintColor = [UIColor redColor];
            cell.textLabel.textColor = [UIColor redColor];
        }

        if ([data[@"type"] isEqualToString:@"link"]) {
            cell.accessoryView = [[UIImageView alloc] initWithImage:[UIImage systemImageNamed:@"safari"]];
        }

        return cell;
    }

    return cell;
}

- (UISwitch *)switchForKey:(NSString *)key {
    UISwitch *switchControl = [[UISwitch alloc] init];
    switchControl.onTintColor = [UIColor colorWithRed:0.75 green:0.50 blue:0.90 alpha:1.0];
    switchControl.on = [[RMAUserDefaults standardUserDefaults] boolForKey:key];
    switchControl.visualElement.showsOnOffLabel = YES;

    [switchControl addTarget:self action:@selector(toggleSwitch:) forControlEvents:UIControlEventValueChanged];

    return switchControl;
}

- (UISlider *)sliderWithKey:(NSString *)key min:(CGFloat)min max:(CGFloat)max {
    UISlider *slider = [[UISlider alloc] init];
    slider.minimumValue = min;
    slider.maximumValue = max;
    slider.value = [[RMAUserDefaults standardUserDefaults] floatForKey:key];
    slider.translatesAutoresizingMaskIntoConstraints = NO;

    [slider addTarget:self action:@selector(sliderValueChanged:) forControlEvents:UIControlEventValueChanged];

    [slider.heightAnchor constraintEqualToConstant:30.0].active = YES;

    return slider;
}

- (NSString *)valueStringForKey:(NSString *)key value:(CGFloat)value {
    if (value == 301.0 && [key isEqualToString:@"keepAlive"]) {
        return @"∞";
    }

    else if (value == (NSInteger)value) {
        return [NSString stringWithFormat:@"%ld", (NSInteger)value];
    }

    else {
        return [NSString stringWithFormat:@"%.2f", value];
    }
}

- (BOOL)tableView:(UITableView *)tableView shouldHighlightRowAtIndexPath:(NSIndexPath *)indexPath {
    return YES;
}

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    NSArray *settingsData = _sections[indexPath.section];
    NSDictionary *data = settingsData[indexPath.row];

    if ([data[@"type"] isEqualToString:@"bool"]) {
        UITableViewCell *cell = [tableView cellForRowAtIndexPath:indexPath];
        UISwitch *switchControl = (UISwitch *)cell.accessoryView;

        [switchControl setOn:!switchControl.on animated:YES];
        [self toggleSwitch:switchControl];
    }

    if ([data[@"type"] isEqualToString:@"reset"]) {
        [RMAUserDefaults resetUserDefaults];
        [tableView reloadData];
    }

    if ([data[@"type"] isEqualToString:@"link"]) {
        NSURL *url = [NSURL URLWithString:data[@"key"]];
        if ([[UIApplication sharedApplication] canOpenURL:url]) {
            [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
        }
    }

    [tableView deselectRowAtIndexPath:indexPath animated:YES];

}

- (void)toggleSwitch:(UISwitch *)sender {
    NSInteger tag = sender.tag;
    NSInteger section = SECTION_FROM_TAG(tag);
    NSInteger row = ROW_FROM_TAG(tag);

    NSDictionary *data = _sections[section][row];
    if (data) {
        [[RMAUserDefaults standardUserDefaults] setBool:sender.isOn forKey:data[@"key"]];
    }
}

- (void)sliderValueChanged:(UISlider *)sender {
    NSInteger tag = sender.tag;
    NSInteger section = SECTION_FROM_TAG(tag);
    NSInteger row = ROW_FROM_TAG(tag);

    NSDictionary *data = _sections[section][row];

    if (data) {
        sender.value = round(sender.value / [data[@"divider"] floatValue]) * [data[@"divider"] floatValue];
        [[RMAUserDefaults standardUserDefaults] setFloat:sender.value forKey:data[@"key"]];

        NSIndexPath *indexPath = [NSIndexPath indexPathForRow:row inSection:section];
        UITableViewCell *cell = [self.tableView cellForRowAtIndexPath:indexPath];

        cell.detailTextLabel.text = [self valueStringForKey:data[@"key"] value:sender.value];
    }
}

@end
