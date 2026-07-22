package audiodevice

/*
#cgo darwin LDFLAGS: -framework CoreAudio -framework CoreFoundation
#include <CoreAudio/CoreAudio.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdlib.h>
#include <string.h>

static OSStatus defaultOutputDevice(AudioDeviceID *device) {
	AudioObjectPropertyAddress addr = {
		kAudioHardwarePropertyDefaultOutputDevice,
		kAudioObjectPropertyScopeGlobal,
		kAudioObjectPropertyElementMain,
	};
	UInt32 size = sizeof(AudioDeviceID);
	return AudioObjectGetPropertyData(kAudioObjectSystemObject, &addr, 0, NULL, &size, device);
}

static OSStatus deviceName(AudioDeviceID device, char *buf, UInt32 bufLen) {
	if (bufLen == 0) {
		return 0;
	}
	buf[0] = '\0';
	AudioObjectPropertyAddress addr = {
		kAudioObjectPropertyName,
		kAudioObjectPropertyScopeGlobal,
		kAudioObjectPropertyElementMain,
	};
	CFStringRef name = NULL;
	UInt32 size = sizeof(CFStringRef);
	OSStatus status = AudioObjectGetPropertyData(device, &addr, 0, NULL, &size, &name);
	if (status != noErr) {
		return status;
	}
	if (name != NULL) {
		CFStringGetCString(name, buf, bufLen, kCFStringEncodingUTF8);
		CFRelease(name);
	}
	return noErr;
}

static OSStatus nominalSampleRate(AudioDeviceID device, Float64 *rate) {
	AudioObjectPropertyAddress addr = {
		kAudioDevicePropertyNominalSampleRate,
		kAudioObjectPropertyScopeGlobal,
		kAudioObjectPropertyElementMain,
	};
	UInt32 size = sizeof(Float64);
	return AudioObjectGetPropertyData(device, &addr, 0, NULL, &size, rate);
}

static OSStatus setNominalSampleRate(AudioDeviceID device, Float64 rate) {
	AudioObjectPropertyAddress addr = {
		kAudioDevicePropertyNominalSampleRate,
		kAudioObjectPropertyScopeGlobal,
		kAudioObjectPropertyElementMain,
	};
	UInt32 size = sizeof(Float64);
	return AudioObjectSetPropertyData(device, &addr, 0, NULL, size, &rate);
}

static OSStatus nominalSampleRateSettable(AudioDeviceID device, Boolean *settable) {
	AudioObjectPropertyAddress addr = {
		kAudioDevicePropertyNominalSampleRate,
		kAudioObjectPropertyScopeGlobal,
		kAudioObjectPropertyElementMain,
	};
	return AudioObjectIsPropertySettable(device, &addr, settable);
}

static OSStatus supportsNominalSampleRate(AudioDeviceID device, Float64 rate, Boolean *supported) {
	*supported = false;
	AudioObjectPropertyAddress addr = {
		kAudioDevicePropertyAvailableNominalSampleRates,
		kAudioObjectPropertyScopeGlobal,
		kAudioObjectPropertyElementMain,
	};
	UInt32 size = 0;
	OSStatus status = AudioObjectGetPropertyDataSize(device, &addr, 0, NULL, &size);
	if (status != noErr) {
		return status;
	}
	if (size == 0) {
		return noErr;
	}
	AudioValueRange *ranges = (AudioValueRange *)malloc(size);
	if (ranges == NULL) {
		return -1;
	}
	status = AudioObjectGetPropertyData(device, &addr, 0, NULL, &size, ranges);
	if (status == noErr) {
		UInt32 count = size / sizeof(AudioValueRange);
		for (UInt32 i = 0; i < count; i++) {
			if (rate >= ranges[i].mMinimum - 0.5 && rate <= ranges[i].mMaximum + 0.5) {
				*supported = true;
				break;
			}
		}
	}
	free(ranges);
	return status;
}
*/
import "C"

import (
	"fmt"
	"strings"
	"unicode"
	"unsafe"
)

type Device struct {
	ID                 uint32
	Name               string
	NominalSampleRate  float64
	SampleRateSettable bool
}

func DefaultOutputDevice() (Device, error) {
	var deviceID C.AudioDeviceID
	if status := C.defaultOutputDevice(&deviceID); status != 0 {
		return Device{}, statusError("default output device", status)
	}
	if deviceID == 0 {
		return Device{}, fmt.Errorf("default output device is not available")
	}

	var rate C.Float64
	if status := C.nominalSampleRate(deviceID, &rate); status != 0 {
		return Device{}, statusError("read output sample rate", status)
	}

	var settable C.Boolean
	if status := C.nominalSampleRateSettable(deviceID, &settable); status != 0 {
		return Device{}, statusError("inspect output sample-rate mutability", status)
	}

	nameBuf := make([]byte, 256)
	namePtr := (*C.char)(unsafe.Pointer(&nameBuf[0]))
	name := "unknown"
	if status := C.deviceName(deviceID, namePtr, C.UInt32(len(nameBuf))); status == 0 {
		if trimmed := strings.TrimRight(string(nameBuf), "\x00"); strings.TrimSpace(trimmed) != "" {
			name = trimmed
		}
	}

	return Device{
		ID:                 uint32(deviceID),
		Name:               name,
		NominalSampleRate:  float64(rate),
		SampleRateSettable: settable != 0,
	}, nil
}

func SupportsDefaultOutputSampleRate(rate float64) (bool, error) {
	var deviceID C.AudioDeviceID
	if status := C.defaultOutputDevice(&deviceID); status != 0 {
		return false, statusError("default output device", status)
	}
	var supported C.Boolean
	if status := C.supportsNominalSampleRate(deviceID, C.Float64(rate), &supported); status != 0 {
		return false, statusError("inspect supported output sample rates", status)
	}
	return supported != 0, nil
}

func SetDefaultOutputSampleRate(rate float64) error {
	var deviceID C.AudioDeviceID
	if status := C.defaultOutputDevice(&deviceID); status != 0 {
		return statusError("default output device", status)
	}
	if status := C.setNominalSampleRate(deviceID, C.Float64(rate)); status != 0 {
		return statusError("set output sample rate", status)
	}
	return nil
}

func statusError(op string, status C.OSStatus) error {
	code := int32(status)
	return fmt.Errorf("%s: CoreAudio status %d (%s)", op, code, osStatusFourCC(code))
}

func osStatusFourCC(code int32) string {
	u := uint32(code)
	runes := []rune{
		rune((u >> 24) & 0xff),
		rune((u >> 16) & 0xff),
		rune((u >> 8) & 0xff),
		rune(u & 0xff),
	}
	for _, r := range runes {
		if !unicode.IsPrint(r) {
			return "not printable"
		}
	}
	return string(runes)
}
