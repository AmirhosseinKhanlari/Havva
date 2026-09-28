# Build EvasionKit.dylib as a non-jailbroken (fishhook) dylib.
#
#   git clone https://github.com/facebook/fishhook   # or reuse the one in
#                                                     # ../../SideloadFix-main/Tweak/fishhook
#   export THEOS=~/theos
#   make FINALPACKAGE=1
#   cp .theos/obj/EvasionKit.dylib ../../EvasionKit.dylib
#
# The pipeline (instrument.py) looks for EvasionKit.dylib in the project root.

ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0
FISHHOOK ?= ../../SideloadFix-main/Tweak/fishhook

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = EvasionKit
EvasionKit_FILES = EvasionKit.c $(FISHHOOK)/fishhook.c
EvasionKit_CFLAGS = -fobjc-arc -I$(FISHHOOK) -Wno-unused
EvasionKit_INSTALL_PATH = /Library/Frameworks

include $(THEOS)/makefiles/library.mk
