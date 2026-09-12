// D3D11 side of the Magpie DLSSNR cross-process bridge probe.
// It creates the same NT-shared texture/fence primitives used by Magpie,
// launches nvngx.dll, waits for one DLSSNR evaluation, and reads the output.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <d3d11_4.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include "bridge_protocol.h"

#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;
using namespace MagpieDlssnrBridge;

namespace {

void Log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    fputc('\n', stdout);
    fflush(stdout);
    va_end(args);
}

std::filesystem::path ExePath() {
    std::wstring buf(32768, L'\0');
    DWORD n = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
    if (!n || n >= buf.size()) return {};
    buf.resize(n);
    return std::filesystem::path(buf);
}

ComPtr<IDXGIAdapter1> PickNvidiaAdapter() {
    ComPtr<IDXGIFactory6> factory;
    if (FAILED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)))) return {};

    for (UINT i = 0;; ++i) {
        ComPtr<IDXGIAdapter1> adapter;
        HRESULT hr = factory->EnumAdapterByGpuPreference(
            i, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
            IID_PPV_ARGS(&adapter));
        if (hr == DXGI_ERROR_NOT_FOUND) break;
        if (FAILED(hr)) continue;

        DXGI_ADAPTER_DESC1 desc{};
        if (FAILED(adapter->GetDesc1(&desc))) continue;
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) continue;
        if (desc.VendorId != 0x10DE) continue;

        char name[256]{};
        WideCharToMultiByte(
            CP_UTF8, 0, desc.Description, -1,
            name, static_cast<int>(sizeof(name)), nullptr, nullptr);
        Log("DXGI: selected %s", name);
        return adapter;
    }
    return {};
}

bool CreateNamedSharedTexture(
    ID3D11Device5* device,
    uint32_t width,
    uint32_t height,
    const std::wstring& name,
    ComPtr<ID3D11Texture2D>& texture) {
    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags =
        D3D11_BIND_SHADER_RESOURCE |
        D3D11_BIND_UNORDERED_ACCESS;
    desc.CPUAccessFlags = 0;
    desc.MiscFlags =
        D3D11_RESOURCE_MISC_SHARED |
        D3D11_RESOURCE_MISC_SHARED_NTHANDLE;

    HRESULT hr = device->CreateTexture2D(
        &desc, nullptr, &texture);
    if (FAILED(hr)) {
        Log("D3D11: CreateTexture2D(%ls) failed hr=0x%08x",
            name.c_str(), static_cast<unsigned>(hr));
        return false;
    }

    ComPtr<IDXGIResource1> dxgi;
    hr = texture.As(&dxgi);
    if (FAILED(hr)) return false;

    HANDLE h = nullptr;
    hr = dxgi->CreateSharedHandle(
        nullptr, GENERIC_ALL, name.c_str(), &h);
    if (FAILED(hr)) {
        Log("D3D11: CreateSharedHandle(%ls) failed hr=0x%08x",
            name.c_str(), static_cast<unsigned>(hr));
        return false;
    }
    CloseHandle(h);
    Log("D3D11: created %ls", name.c_str());
    return true;
}

bool CreateNamedSharedFence(
    ID3D11Device5* device,
    const std::wstring& name,
    ComPtr<ID3D11Fence>& fence) {
    HRESULT hr = device->CreateFence(
        0, D3D11_FENCE_FLAG_SHARED, IID_PPV_ARGS(&fence));
    if (FAILED(hr)) {
        Log("D3D11: CreateFence failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return false;
    }

    HANDLE h = nullptr;
    hr = fence->CreateSharedHandle(
        nullptr, GENERIC_ALL, name.c_str(), &h);
    if (FAILED(hr)) {
        Log("D3D11: fence CreateSharedHandle failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return false;
    }
    CloseHandle(h);
    Log("D3D11: created %ls", name.c_str());
    return true;
}

bool FillInput(
    ID3D11DeviceContext4* context,
    ID3D11Texture2D* input,
    uint32_t width,
    uint32_t height) {
    std::vector<uint32_t> pixels(size_t(width) * size_t(height));
    for (uint32_t y = 0; y < height; ++y) {
        for (uint32_t x = 0; x < width; ++x) {
            const uint8_t r = static_cast<uint8_t>((x * 255u) / (width - 1));
            const uint8_t g = static_cast<uint8_t>((y * 255u) / (height - 1));
            const uint8_t b = static_cast<uint8_t>(
                ((x / 32 + y / 32) & 1) ? 220 : 30);
            const uint8_t a = 255;
            pixels[size_t(y) * width + x] =
                uint32_t(r) |
                (uint32_t(g) << 8) |
                (uint32_t(b) << 16) |
                (uint32_t(a) << 24);
        }
    }

    context->UpdateSubresource(
        input, 0, nullptr, pixels.data(),
        width * sizeof(uint32_t), 0);
    return true;
}

bool ReadOutput(
    ID3D11Device5* device,
    ID3D11DeviceContext4* context,
    ID3D11Texture2D* output,
    uint32_t width,
    uint32_t height) {
    D3D11_TEXTURE2D_DESC desc{};
    output->GetDesc(&desc);
    desc.BindFlags = 0;
    desc.MiscFlags = 0;
    desc.Usage = D3D11_USAGE_STAGING;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;

    ComPtr<ID3D11Texture2D> staging;
    HRESULT hr = device->CreateTexture2D(
        &desc, nullptr, &staging);
    if (FAILED(hr)) {
        Log("READBACK: staging CreateTexture2D failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return false;
    }

    context->CopyResource(staging.Get(), output);
    context->Flush();

    D3D11_MAPPED_SUBRESOURCE mapped{};
    hr = context->Map(
        staging.Get(), 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(hr)) {
        Log("READBACK: Map failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return false;
    }

    uint64_t hash = 1469598103934665603ull;
    uint64_t nonZero = 0;
    uint64_t samples = 0;

    for (uint32_t y = 0; y < height; ++y) {
        const auto* row = reinterpret_cast<const uint8_t*>(
            mapped.pData) + size_t(y) * mapped.RowPitch;
        for (uint32_t x = 0; x < width * 4u; x += 4u) {
            const uint32_t pixel =
                uint32_t(row[x + 0]) |
                (uint32_t(row[x + 1]) << 8) |
                (uint32_t(row[x + 2]) << 16) |
                (uint32_t(row[x + 3]) << 24);
            hash ^= pixel;
            hash *= 1099511628211ull;
            if (pixel != 0) ++nonZero;
            ++samples;
        }
    }

    context->Unmap(staging.Get(), 0);

    Log("READBACK: pixels=%llu nonzero=%llu hash=0x%016llx",
        static_cast<unsigned long long>(samples),
        static_cast<unsigned long long>(nonZero),
        static_cast<unsigned long long>(hash));

    return nonZero > 0;
}

bool SpawnWorker(
    const std::filesystem::path& worker,
    const std::wstring& session,
    uint32_t width,
    uint32_t height,
    PROCESS_INFORMATION& pi) {
    std::wstring command = L"\"" + worker.wstring() +
        L"\" --bridge-probe \"" + session + L"\" " +
        std::to_wstring(width) + L" " + std::to_wstring(height);

    STARTUPINFOW si{};
    si.cb = sizeof(si);

    std::vector<wchar_t> mutableCommand(
        command.begin(), command.end());
    mutableCommand.push_back(L'\0');

    const BOOL ok = CreateProcessW(
        worker.c_str(),
        mutableCommand.data(),
        nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW,
        nullptr,
        worker.parent_path().c_str(),
        &si, &pi);

    if (!ok) {
        Log("PROCESS: CreateProcess(%ls) failed win32=%lu",
            worker.c_str(), GetLastError());
        return false;
    }

    Log("PROCESS: worker pid=%lu", pi.dwProcessId);
    return true;
}

} // namespace

int wmain() {
    constexpr uint32_t kWidth = 1280;
    constexpr uint32_t kHeight = 720;

    const auto exe = ExePath();
    if (exe.empty()) {
        Log("FATAL: cannot resolve client path");
        return 2;
    }

    const auto dir = exe.parent_path();
    const auto worker = dir / L"nvngx.dll";
    const auto runtime = dir / L"nvngx_dlssnr.dll";
    if (!std::filesystem::exists(worker)) {
        Log("FATAL: missing %ls", worker.c_str());
        return 3;
    }
    if (!std::filesystem::exists(runtime)) {
        Log("FATAL: missing %ls", runtime.c_str());
        return 4;
    }

    const std::wstring session =
        std::to_wstring(GetCurrentProcessId());

    auto adapter = PickNvidiaAdapter();
    if (!adapter) {
        Log("FATAL: NVIDIA adapter not found");
        return 5;
    }

    UINT flags = D3D11_CREATE_DEVICE_BGRA_SUPPORT;
    D3D_FEATURE_LEVEL levels[]{
        D3D_FEATURE_LEVEL_12_1,
        D3D_FEATURE_LEVEL_12_0,
        D3D_FEATURE_LEVEL_11_1,
        D3D_FEATURE_LEVEL_11_0
    };

    ComPtr<ID3D11Device> baseDevice;
    ComPtr<ID3D11DeviceContext> baseContext;
    D3D_FEATURE_LEVEL actual{};
    HRESULT hr = D3D11CreateDevice(
        adapter.Get(),
        D3D_DRIVER_TYPE_UNKNOWN,
        nullptr,
        flags,
        levels,
        ARRAYSIZE(levels),
        D3D11_SDK_VERSION,
        &baseDevice,
        &actual,
        &baseContext);
    if (FAILED(hr)) {
        Log("FATAL: D3D11CreateDevice failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return 6;
    }

    ComPtr<ID3D11Device5> device;
    ComPtr<ID3D11DeviceContext4> context;
    if (FAILED(baseDevice.As(&device)) ||
        FAILED(baseContext.As(&context))) {
        Log("FATAL: D3D11.4 interfaces unavailable");
        return 7;
    }

    Log("D3D11: device created featureLevel=0x%x",
        static_cast<unsigned>(actual));

    ComPtr<ID3D11Texture2D> input;
    ComPtr<ID3D11Texture2D> output;
    ComPtr<ID3D11Fence> fence;

    if (!CreateNamedSharedTexture(
            device.Get(), kWidth, kHeight,
            InputName(session), input) ||
        !CreateNamedSharedTexture(
            device.Get(), kWidth, kHeight,
            OutputName(session), output) ||
        !CreateNamedSharedFence(
            device.Get(), FenceName(session), fence)) {
        return 8;
    }

    FillInput(context.Get(), input.Get(), kWidth, kHeight);

    // Ensure input writes are queued before advertising fence value 1.
    hr = context->Signal(
        fence.Get(), kInputReadyFenceValue);
    if (FAILED(hr)) {
        Log("FENCE: input signal failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return 9;
    }
    context->Flush();
    Log("FENCE: input signaled value=%llu",
        static_cast<unsigned long long>(kInputReadyFenceValue));

    PROCESS_INFORMATION pi{};
    if (!SpawnWorker(worker, session, kWidth, kHeight, pi)) {
        return 10;
    }

    HANDLE eventHandle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!eventHandle) {
        TerminateProcess(pi.hProcess, 99);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 11;
    }

    hr = fence->SetEventOnCompletion(
        kOutputReadyFenceValue, eventHandle);
    if (FAILED(hr)) {
        Log("FENCE: SetEventOnCompletion failed hr=0x%08x",
            static_cast<unsigned>(hr));
        TerminateProcess(pi.hProcess, 99);
        CloseHandle(eventHandle);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 12;
    }

    const DWORD wait = WaitForSingleObject(eventHandle, 30000);
    CloseHandle(eventHandle);

    if (wait != WAIT_OBJECT_0) {
        Log("FENCE: output timeout; worker log should explain the failure");
        WaitForSingleObject(pi.hProcess, 1000);
        DWORD exitCode = STILL_ACTIVE;
        GetExitCodeProcess(pi.hProcess, &exitCode);
        Log("PROCESS: worker exit code=%lu", exitCode);
        if (exitCode == STILL_ACTIVE) {
            TerminateProcess(pi.hProcess, 98);
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 13;
    }

    Log("FENCE: output ready value=%llu",
        static_cast<unsigned long long>(kOutputReadyFenceValue));

    const bool outputValid = ReadOutput(
        device.Get(), context.Get(), output.Get(), kWidth, kHeight);

    WaitForSingleObject(pi.hProcess, 10000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    Log("PROCESS: worker exit code=%lu", exitCode);

    if (outputValid && exitCode == 0) {
        Log("SUCCESS: D3D11 -> nvngx.dll/D3D12 -> D3D11 bridge works");
        return 0;
    }

    Log("FAIL: bridge did not produce a valid frame");
    return 20;
}
