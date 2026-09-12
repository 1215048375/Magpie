#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

namespace MagpieDlssnrBridge {

constexpr uint64_t kInputReadyFenceValue = 1;
constexpr uint64_t kOutputReadyFenceValue = 2;

inline std::wstring MakeObjectName(
    const wchar_t* kind,
    const std::wstring& session) {
    return std::wstring(L"Local\\MagpieDLSSNR_") + session + L"_" + kind;
}

inline std::wstring InputName(const std::wstring& session) {
    return MakeObjectName(L"Input", session);
}

inline std::wstring OutputName(const std::wstring& session) {
    return MakeObjectName(L"Output", session);
}

inline std::wstring FenceName(const std::wstring& session) {
    return MakeObjectName(L"Fence", session);
}

}
