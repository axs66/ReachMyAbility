ifeq ($(ROOTLESS),1)
THEOS_PACKAGE_SCHEME = rootless
else ifeq ($(ROOTHIDE),1)
THEOS_PACKAGE_SCHEME = roothide
endif

DEBUG = 0
FINALPACKAGE = 1
TARGET := iphone:clang:16.5:14.0
PACKAGE_VERSION = 1.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ReachMyAbility
$(TWEAK_NAME)_FILES = Tweak.x RMAPrefs/RMAUserDefaults.m
$(TWEAK_NAME)_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk

SUBPROJECTS += RMAPrefs

include $(THEOS_MAKE_PATH)/aggregate.mk

