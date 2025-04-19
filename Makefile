TARGET = iphone:clang:latest:15.0
ARCHS = arm64 arm64e

#export THEOS=/Users/huami/theos
#export THEOS_PACKAGE_SCHEME=roothide

ifeq ($(SCHEME),roothide)
    export THEOS_PACKAGE_SCHEME = roothide
else ifeq ($(SCHEME),rootless)
    export THEOS_PACKAGE_SCHEME = rootless
endif

TWEAK_NAME = WCFullSwipe
PACKAGE_VERSION = 1.3
DEBUG = 0

WCFullSwipe_FILES = Tweak.x
WCFullSwipe_CFLAGS = -fobjc-arc

include $(THEOS)/makefiles/common.mk
include $(THEOS)/makefiles/tweak.mk

THEOS_DEVICE_IP = 192.168.31.222
THEOS_DEVICE_PORT = 22

clean::
	@echo -e "\033[31m==>\033[0m Cleaning packages…"
	@rm -rf .theos packages

after-package::
	@if [ "$(THEOS_PACKAGE_SCHEME)" = "roothide" ] && [ "$(INSTALL)" = "1" ]; then \
	echo -e "\033[31m==>\033[0m Installing package to device…"; \
	DEB_FILE=$$(ls -t packages/*.deb | head -1); \
	PACKAGE_NAME=$$(basename "$$DEB_FILE" | cut -d'_' -f1); \
	ssh root@$(THEOS_DEVICE_IP) "rm -rf /tmp/$${PACKAGE_NAME}.deb"; \
	scp "$$DEB_FILE" root@$(THEOS_DEVICE_IP):/tmp/$${PACKAGE_NAME}.deb; \
	ssh root@$(THEOS_DEVICE_IP) "dpkg -i --force-overwrite /tmp/$${PACKAGE_NAME}.deb && rm -f /tmp/$${PACKAGE_NAME}.deb"; \
	fi
