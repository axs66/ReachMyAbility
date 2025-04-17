// Auto-generated Tweak.xm

%hook /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation
    %orig;
    NSLog(@"[Tweak] Hooked /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
%end

%hook /System/Library/Frameworks/Foundation.framework/Foundation
    %orig;
    NSLog(@"[Tweak] Hooked /System/Library/Frameworks/Foundation.framework/Foundation");
%end

%hook /usr/lib/libSystem.B.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/libSystem.B.dylib");
%end

%hook /usr/lib/libc++.1.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/libc++.1.dylib");
%end

%hook /usr/lib/libobjc.A.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/libobjc.A.dylib");
%end

%hook /usr/lib/swift/libswiftCore.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftCore.dylib");
%end

%hook /usr/lib/swift/libswiftCoreFoundation.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftCoreFoundation.dylib");
%end

%hook /usr/lib/swift/libswiftCoreGraphics.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftCoreGraphics.dylib");
%end

%hook /usr/lib/swift/libswiftCoreImage.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftCoreImage.dylib");
%end

%hook /usr/lib/swift/libswiftDarwin.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftDarwin.dylib");
%end

%hook /usr/lib/swift/libswiftDataDetection.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftDataDetection.dylib");
%end

%hook /usr/lib/swift/libswiftDispatch.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftDispatch.dylib");
%end

%hook /usr/lib/swift/libswiftFileProvider.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftFileProvider.dylib");
%end

%hook /usr/lib/swift/libswiftFoundation.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftFoundation.dylib");
%end

%hook /usr/lib/swift/libswiftMetal.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftMetal.dylib");
%end

%hook /usr/lib/swift/libswiftObjectiveC.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftObjectiveC.dylib");
%end

%hook /usr/lib/swift/libswiftQuartzCore.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftQuartzCore.dylib");
%end

%hook /usr/lib/swift/libswiftUIKit.dylib
    %orig;
    NSLog(@"[Tweak] Hooked /usr/lib/swift/libswiftUIKit.dylib");
%end

%hook 0x0000010ba0:
    %orig;
    NSLog(@"[Tweak] Hooked 0x0000010ba0:");
%end

%hook @rpath/Orion.framework/Orion
    %orig;
    NSLog(@"[Tweak] Hooked @rpath/Orion.framework/Orion");
%end

%hook @rpath/WechatPushMsgPage.dylib
    %orig;
    NSLog(@"[Tweak] Hooked @rpath/WechatPushMsgPage.dylib");
%end

%hook OS_dispatch_queue
    %orig;
    NSLog(@"[Tweak] Hooked OS_dispatch_queue");
%end

%hook _TtCs12_SwiftObject
    %orig;
    NSLog(@"[Tweak] Hooked _TtCs12_SwiftObject");
%end

