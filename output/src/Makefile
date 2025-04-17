ARCHS = arm64
TARGET = iphone:latest:13.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = WechatPushMsgPage

WechatPushMsgPage_FILES = Tweak.xm
WechatPushMsgPage_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
