#import "CSCustomViewController.h"
#import "CSSettingTableViewCell.h"
#import "CSInputTextSettingsViewController.h"
#import "CSEntrySettingsViewController.h"

@interface CSCustomViewController () <UITableViewDelegate, UITableViewDataSource>
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) NSArray<CSSettingSection *> *sections;
@end

@implementation CSCustomViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.title = @"微信设置";
    [self setupUI];
    [self setupData];
}

- (void)setupData {
    // 功能增强组
    CSSettingItem *inputTextItem = [CSSettingItem itemWithTitle:@"文本占位"
                                                      iconName:@"text.bubble.fill"
                                                     iconColor:[UIColor systemPinkColor]
                                                       detail:nil];
    
    CSSettingSection *enhancementSection = [CSSettingSection sectionWithHeader:@"功能增强" 
                                                                      items:@[inputTextItem]];
    
    // 插件设置组
    CSSettingItem *entrySettingsItem = [CSSettingItem itemWithTitle:@"入口设置"
                                                         iconName:@"door.right.hand.open"
                                                        iconColor:[UIColor systemBrownColor]
                                                          detail:nil];
    
    CSSettingSection *pluginSection = [CSSettingSection sectionWithHeader:@"插件设置"
                                                                 items:@[entrySettingsItem]];
    
    self.sections = @[enhancementSection, pluginSection];
}

- (void)setupUI {
    self.view.backgroundColor = [UIColor systemGroupedBackgroundColor];
    
    self.tableView = [[UITableView alloc] initWithFrame:self.view.bounds style:UITableViewStyleInsetGrouped];
    self.tableView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    self.tableView.backgroundColor = [UIColor systemGroupedBackgroundColor];
    self.tableView.separatorStyle = UITableViewCellSeparatorStyleSingleLine;
    self.tableView.separatorInset = UIEdgeInsetsMake(0, 54, 0, 0);
    
    self.tableView.delegate = self;
    self.tableView.dataSource = self;
    
    [CSSettingTableViewCell registerToTableView:self.tableView];
    [self.view addSubview:self.tableView];
}

#pragma mark - UITableViewDataSource

- (NSInteger)numberOfSectionsInTableView:(UITableView *)tableView {
    return self.sections.count;
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    return self.sections[section].items.count;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    CSSettingTableViewCell *cell = [tableView dequeueReusableCellWithIdentifier:[CSSettingTableViewCell reuseIdentifier]];
    CSSettingItem *item = self.sections[indexPath.section].items[indexPath.row];
    [cell configureWithItem:item];
    return cell;
}

- (NSString *)tableView:(UITableView *)tableView titleForHeaderInSection:(NSInteger)section {
    return self.sections[section].header;
}

#pragma mark - UITableViewDelegate

- (void)tableView:(UITableView *)tableView didSelectRowAtIndexPath:(NSIndexPath *)indexPath {
    [tableView deselectRowAtIndexPath:indexPath animated:YES];
    
    CSSettingItem *item = self.sections[indexPath.section].items[indexPath.row];
    
    if ([item.title isEqualToString:@"文本占位"]) {
        CSInputTextSettingsViewController *inputTextVC = [[CSInputTextSettingsViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
        [self.navigationController pushViewController:inputTextVC animated:YES];
    }
    else if ([item.title isEqualToString:@"入口设置"]) {
        CSEntrySettingsViewController *entrySettingsVC = [[CSEntrySettingsViewController alloc] initWithStyle:UITableViewStyleInsetGrouped];
        [self.navigationController pushViewController:entrySettingsVC animated:YES];
    }
}

- (void)tableView:(UITableView *)tableView willDisplayCell:(UITableViewCell *)cell forRowAtIndexPath:(NSIndexPath *)indexPath {
    if (@available(iOS 13.0, *)) {
        cell.backgroundColor = [UIColor secondarySystemGroupedBackgroundColor];
    } else {
        cell.backgroundColor = [UIColor whiteColor];
    }
    
    UIView *selectedBackgroundView = [[UIView alloc] init];
    if (@available(iOS 13.0, *)) {
        selectedBackgroundView.backgroundColor = [UIColor tertiarySystemGroupedBackgroundColor];
    } else {
        selectedBackgroundView.backgroundColor = [UIColor systemGray5Color];
    }
    cell.selectedBackgroundView = selectedBackgroundView;
}

@end
