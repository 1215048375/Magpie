#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <string_view>

namespace Magpie::DLSSNRWorkerProtocol {

inline constexpr uint32_t MAGIC = 0x4D4E5257u; // "MNRW"
inline constexpr uint32_t VERSION = 2;

enum class WorkerState : LONG {
	Starting = 0,
	Ready = 1,
	Running = 2,
	Failed = -1,
	Stopping = -2
};

struct ControlBlock {
	uint32_t magic = MAGIC;
	uint32_t version = VERSION;
	uint32_t width = 0;
	uint32_t height = 0;
	uint32_t colorFormat = 0;
	uint32_t reserved0 = 0;

	volatile LONG settingsRevision = 0;
	volatile LONG resetHistory = 1;
	volatile LONG workerState = static_cast<LONG>(WorkerState::Starting);
	volatile LONG lastResult = 0;
	volatile LONG64 lastCompletedFence = 0;

	int32_t style = 0;
	float intensity = 1.0f;
	float localToneStrength = 1.0f;
	float localStructureStrength = 1.0f;
	float skinStructureStrength = 0.0f;
	uint32_t useAutoMask = 0;
	uint32_t uiCorrection = 0;
	uint32_t motionBaseX = 0;
	uint32_t motionBaseY = 0;
	uint32_t motionWidth = 0;
	uint32_t motionHeight = 0;
};

inline std::wstring ObjectName(
	std::wstring_view session,
	std::wstring_view suffix
) {
	std::wstring result = L"Local\\MagpieDLSSNR_";
	result.append(session);
	result.push_back(L'_');
	result.append(suffix);
	return result;
}

inline std::wstring InputName(std::wstring_view session) {
	return ObjectName(session, L"Input");
}

inline std::wstring OutputName(std::wstring_view session) {
	return ObjectName(session, L"Output");
}

inline std::wstring MotionName(std::wstring_view session) {
	return ObjectName(session, L"Motion");
}

inline std::wstring FenceName(std::wstring_view session) {
	return ObjectName(session, L"Fence");
}

inline std::wstring ControlName(std::wstring_view session) {
	return ObjectName(session, L"Control");
}

inline std::wstring ReadyName(std::wstring_view session) {
	return ObjectName(session, L"Ready");
}

inline std::wstring StopName(std::wstring_view session) {
	return ObjectName(session, L"Stop");
}

}
