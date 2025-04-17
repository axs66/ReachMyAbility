ARCHS = arm64
TARGET = iphone:latest:13.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Plugin

Plugin_FILES = Tweak.xm
Plugin_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
