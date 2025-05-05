ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:11.0
INSTALL_TARGET_PROCESSES = WeChat

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WeChatTweak

WeChatTweak_FILES = $(wildcard src/*.m) $(wildcard src/*.xm)
WeChatTweak_CFLAGS = -fobjc-arc
WeChatTweak_FRAMEWORKS = UIKit CoreGraphics
WeChatTweak_PRIVATE_FRAMEWORKS = Preferences

include $(THEOS)/makefiles/tweak.mk

after-install::
	install.exec "killall -9 WeChat"
