#import <UIKit/UIKit.h>

@interface MMUIViewController : UIViewController
@property (nonatomic, readonly) UINavigationController *navigationController;
@end

%hook MMUIViewController

- (void)viewDidLoad {
    %orig;

    UIGestureRecognizer *edgeGesture = self.navigationController.interactivePopGestureRecognizer;
    edgeGesture.enabled = YES;

    NSArray *targets = [edgeGesture valueForKey:@"_targets"];
    id targetObj = [targets.firstObject valueForKey:@"target"];
    SEL action = NSSelectorFromString(@"handleNavigationTransition:");

    UIPanGestureRecognizer *fullScreenPan = [[UIPanGestureRecognizer alloc] initWithTarget:targetObj action:action];
    fullScreenPan.delegate = (id<UIGestureRecognizerDelegate>)self;
    
    fullScreenPan.maximumNumberOfTouches = 1;
    
    fullScreenPan.cancelsTouchesInView = NO;
    
    [self.view addGestureRecognizer:fullScreenPan];
}

- (BOOL)gestureRecognizerShouldBegin:(UIGestureRecognizer *)gestureRecognizer {

    if ([gestureRecognizer isKindOfClass:[UIPanGestureRecognizer class]] && 
        gestureRecognizer != self.navigationController.interactivePopGestureRecognizer) {
        UIPanGestureRecognizer *panGesture = (UIPanGestureRecognizer *)gestureRecognizer;
        
        CGPoint location = [panGesture locationInView:self.view];
        CGFloat screenWidth = self.view.bounds.size.width;
        
        BOOL isInMiddleArea = location.x > screenWidth/3 && location.x < screenWidth*2/3;
        
        CGPoint translation = [panGesture translationInView:self.view];
        BOOL isHorizontalSwipe = fabs(translation.x) > fabs(translation.y);
        BOOL isRightSwipe = translation.x > 0;
        
        return isInMiddleArea && isHorizontalSwipe && isRightSwipe;
    }
    
    return %orig;
}

- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer {

    if (gestureRecognizer != self.navigationController.interactivePopGestureRecognizer && 
        [gestureRecognizer isKindOfClass:[UIPanGestureRecognizer class]]) {
        
        if (otherGestureRecognizer == self.navigationController.interactivePopGestureRecognizer) {
            return NO;
        }
        
        return NO;
    }
    
    return NO;
}

%end