# implant/Application.mk
# Per-ABI: both arm64-v8a and armeabi-v7a (the daemon carries both ABIs)
APP_ABI := arm64-v8a armeabi-v7a
APP_PLATFORM := android-28
# c++_static: system libc++_shared.so on Android 9 conflicts by ABI
APP_STL := c++_static
