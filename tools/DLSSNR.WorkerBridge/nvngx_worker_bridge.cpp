// Magpie DLSSNR cross-process bridge probe.
//
// This executable PE is intentionally named nvngx.dll.
// It opens D3D11-created NT-shared textures/fence by name, runs one DLSSNR
// Feature 18 evaluation on D3D12, then signals the shared fence.
//
// Runtime directory:
//   nvngx.dll
//   nvngx_dlssnr.dll
//   magpie-dlssnr-bridge-client.exe
//
// This is a transport proof, not yet the production Magpie backend.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <d3d12.h>
#include <dxgi1_6.h>
#include <wrl/client.h>

#include <nvsdk_ngx.h>
#include <nvsdk_ngx_defs.h>

#include "bridge_protocol.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdarg>
#include <cstdio>
#include <cwctype>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <string>
#include <vector>

using Microsoft::WRL::ComPtr;
using namespace MagpieDlssnrBridge;

namespace {

constexpr unsigned long long kDlssNrApplicationId = 0x0876232Cull;
constexpr NVSDK_NGX_Feature kFeatureDlssNr =
    static_cast<NVSDK_NGX_Feature>(18);

constexpr uint32_t kNvapiIdGpuGetArchInfo = 0xD8265D24u;
constexpr uint32_t kArchAmpere = 0x0170u;
constexpr uint32_t kArchBlackwell2 = 0x01B0u;
constexpr size_t kHookSize = 12;

FILE* g_log = nullptr;

void Log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (g_log) {
        vfprintf(g_log, fmt, args);
        fputc('\n', g_log);
        fflush(g_log);
    }
    va_end(args);

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

struct NvGpuArchInfoCompat {
    uint32_t version;
    uint32_t architecture;
    uint32_t implementation;
    uint32_t revision;
};

using NvApiQueryInterfaceFn = void* (__cdecl*)(uint32_t);
using NvApiGpuGetArchInfoFn = int (__cdecl*)(void*, NvGpuArchInfoCompat*);

std::mutex g_archMutex;
NvApiGpuGetArchInfoFn g_archReal = nullptr;
std::array<uint8_t, kHookSize> g_archOriginal{};
bool g_archPatched = false;
std::atomic<bool> g_archLogged = false;

int __cdecl HookedGpuGetArchInfo(void* gpu, NvGpuArchInfoCompat* info);

bool SetArchHook(bool enable) {
    if (!g_archReal) return false;
    auto* target = reinterpret_cast<uint8_t*>(
        reinterpret_cast<uintptr_t>(g_archReal));

    DWORD oldProtect = 0;
    if (!VirtualProtect(target, kHookSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    if (enable) {
        std::array<uint8_t, kHookSize> patch{
            0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xE0
        };
        const uint64_t handler =
            reinterpret_cast<uint64_t>(&HookedGpuGetArchInfo);
        std::memcpy(patch.data() + 2, &handler, sizeof(handler));
        std::memcpy(target, patch.data(), patch.size());
        g_archPatched = true;
    } else {
        std::memcpy(target, g_archOriginal.data(), g_archOriginal.size());
        g_archPatched = false;
    }

    FlushInstructionCache(GetCurrentProcess(), target, kHookSize);
    DWORD ignored = 0;
    VirtualProtect(target, kHookSize, oldProtect, &ignored);
    return true;
}

int __cdecl HookedGpuGetArchInfo(void* gpu, NvGpuArchInfoCompat* info) {
    std::lock_guard lock(g_archMutex);
    if (!SetArchHook(false)) return -1;

    const int status = g_archReal ? g_archReal(gpu, info) : -1;
    SetArchHook(true);

    if (status == 0 && info) {
        const uint32_t real = info->architecture;
        if (real == kArchAmpere) {
            info->architecture = kArchBlackwell2;
            if (!g_archLogged.exchange(true)) {
                Log("ARCH: real=0x%03x spoofed=0x%03x",
                    real, info->architecture);
            }
        } else if (!g_archLogged.exchange(true)) {
            Log("ARCH: observed=0x%03x (not rewritten)", real);
        }
    }

    return status;
}

class ScopedArchSpoof {
public:
    bool Install() {
        module_ = LoadLibraryW(L"nvapi64.dll");
        if (!module_) {
            Log("ARCH: LoadLibrary(nvapi64.dll) failed: %lu", GetLastError());
            return false;
        }

        auto query = reinterpret_cast<NvApiQueryInterfaceFn>(
            GetProcAddress(module_, "nvapi_QueryInterface"));
        if (!query) {
            Log("ARCH: nvapi_QueryInterface missing");
            return false;
        }

        g_archReal = reinterpret_cast<NvApiGpuGetArchInfoFn>(
            query(kNvapiIdGpuGetArchInfo));
        if (!g_archReal) {
            Log("ARCH: NvAPI_GPU_GetArchInfo lookup failed");
            return false;
        }

        std::memcpy(
            g_archOriginal.data(),
            reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(g_archReal)),
            g_archOriginal.size());

        if (!SetArchHook(true)) {
            Log("ARCH: patch failed");
            return false;
        }

        installed_ = true;
        Log("ARCH: hook installed");
        return true;
    }

    ~ScopedArchSpoof() {
        if (installed_ && g_archReal && g_archPatched) {
            std::lock_guard lock(g_archMutex);
            SetArchHook(false);
            Log("ARCH: hook removed");
        }
        g_archReal = nullptr;
        if (module_) FreeLibrary(module_);
    }

private:
    HMODULE module_ = nullptr;
    bool installed_ = false;
};

ComPtr<IDXGIAdapter1> PickNvidiaAdapter() {
    ComPtr<IDXGIFactory6> factory;
    if (FAILED(CreateDXGIFactory2(0, IID_PPV_ARGS(&factory)))) return {};

    for (UINT i = 0;; ++i) {
        ComPtr<IDXGIAdapter1> adapter;
        const HRESULT hr = factory->EnumAdapterByGpuPreference(
            i, DXGI_GPU_PREFERENCE_HIGH_PERFORMANCE,
            IID_PPV_ARGS(&adapter));
        if (hr == DXGI_ERROR_NOT_FOUND) break;
        if (FAILED(hr)) continue;

        DXGI_ADAPTER_DESC1 desc{};
        if (FAILED(adapter->GetDesc1(&desc))) continue;
        if (desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE) continue;

        if (desc.VendorId == 0x10DE) {
            char name[256]{};
            WideCharToMultiByte(
                CP_UTF8, 0, desc.Description, -1,
                name, static_cast<int>(sizeof(name)), nullptr, nullptr);
            Log("DXGI: selected %s vendor=0x%04x device=0x%04x",
                name, desc.VendorId, desc.DeviceId);
            return adapter;
        }
    }
    return {};
}

template <typename T>
T Export(HMODULE module, const char* name) {
    return reinterpret_cast<T>(GetProcAddress(module, name));
}

using SnippetInitExtFn = NVSDK_NGX_Result (NVSDK_CONV*)(
    unsigned long long, const wchar_t*, ID3D12Device*,
    NVSDK_NGX_Version, const NVSDK_NGX_Parameter*);
using SnippetCreateFeatureFn = NVSDK_NGX_Result (NVSDK_CONV*)(
    ID3D12GraphicsCommandList*, NVSDK_NGX_Feature,
    NVSDK_NGX_Parameter*, NVSDK_NGX_Handle**);
using SnippetEvaluateFeatureFn = NVSDK_NGX_Result (NVSDK_CONV*)(
    ID3D12GraphicsCommandList*, const NVSDK_NGX_Handle*,
    const NVSDK_NGX_Parameter*, PFN_NVSDK_NGX_ProgressCallback);
using SnippetReleaseFeatureFn =
    NVSDK_NGX_Result (NVSDK_CONV*)(NVSDK_NGX_Handle*);
using SnippetShutdownFn =
    NVSDK_NGX_Result (NVSDK_CONV*)(ID3D12Device*);

NVSDK_NGX_Result NVSDK_CONV ScalingRatioCallback(
    NVSDK_NGX_Parameter* parameters) {
    if (!parameters) return NVSDK_NGX_Result_FAIL_InvalidParameter;
    parameters->Set("DLSSNR.ScalingRatio", 1.0f);
    return NVSDK_NGX_Result_Success;
}

void SetSubrect(
    NVSDK_NGX_Parameter* p,
    const char* prefix,
    uint32_t width,
    uint32_t height) {
    std::string baseX = std::string(prefix) + "SubrectBaseX";
    std::string baseY = std::string(prefix) + "SubrectBaseY";
    std::string w = std::string(prefix) + "SubrectWidth";
    std::string h = std::string(prefix) + "SubrectHeight";
    p->Set(baseX.c_str(), 0u);
    p->Set(baseY.c_str(), 0u);
    p->Set(w.c_str(), width);
    p->Set(h.c_str(), height);
}

void SetCreateParameters(
    NVSDK_NGX_Parameter* p,
    uint32_t width,
    uint32_t height) {
    p->Set("DLSSNR.Width", width);
    p->Set("DLSSNR.Height", height);
    p->Set("DLSSNR.InputWidth", width);
    p->Set("DLSSNR.InputHeight", height);
    p->Set("DLSSNR.OutputWidth", width);
    p->Set("DLSSNR.OutputHeight", height);
    p->Set("DLSSNR.Output.Width", width);
    p->Set("DLSSNR.Output.Height", height);
    p->Set("DLSSNR.Upscaling", 0u);
    p->Set("DLSSNR.Scale", 1.0f);
    p->Set("DLSSNR.ScalingRatio", 1.0f);
    p->Set(
        "DLSSNRComputeScalingRatioCallback",
        reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(&ScalingRatioCallback)));
    p->Set("DLSSNR.Hint.Render.Preset", 0);

    p->Set(NVSDK_NGX_Parameter_Width, width);
    p->Set(NVSDK_NGX_Parameter_Height, height);
    p->Set(
        NVSDK_NGX_Parameter_PerfQualityValue,
        static_cast<int>(NVSDK_NGX_PerfQuality_Value_Balanced));
    p->Set(NVSDK_NGX_Parameter_CreationNodeMask, 1u);
    p->Set(NVSDK_NGX_Parameter_VisibilityNodeMask, 1u);
}

void SetEvaluateParameters(
    NVSDK_NGX_Parameter* p,
    ID3D12Resource* color,
    ID3D12Resource* output,
    ID3D12Resource* motion,
    ID3D12Resource* depth,
    uint32_t width,
    uint32_t height) {
    p->Set("DLSSNR.Color", color);
    p->Set("DLSSNR.Output", output);
    p->Set("DLSSNR.MVec", motion);
    p->Set("DLSSNR.Depth", depth);

    SetSubrect(p, "DLSSNR.Color", width, height);
    SetSubrect(p, "DLSSNR.Output", width, height);
    SetSubrect(p, "DLSSNR.MVec", width, height);
    SetSubrect(p, "DLSSNR.Depth", width, height);

    p->Set("DLSSNR.MVecScaleX", 1.0f);
    p->Set("DLSSNR.MVecScaleY", 1.0f);
    p->Set("DLSSNR.DepthInverted", 1);
    p->Set("DLSS.Indicator.Invert.X.Axis", 0);
    p->Set("DLSS.Indicator.Invert.Y.Axis", 0);
    p->Set("DLSSNR.Enabled", 1);
    p->Set("DLSSNR.Reset", 1);

    // Neutral/low-risk settings for the transport probe.
    p->Set("DLSSNR.Style", 1);
    p->Set("DLSSNR.Intensity", 1.0f);
    p->Set("DLSSNR.LocalToneStrength", 1.0f);
    p->Set("DLSSNR.LocalStructureStrength", 1.0f);
    p->Set("DLSSNR.SkinStructureStrength", 1.0f);
    p->Set("DLSSNR.UseAutoMask", 1);
    p->Set("DLSSNR.UICorrection", 0);
}

ComPtr<ID3D12Resource> CreateAuxTexture(
    ID3D12Device* device,
    DXGI_FORMAT format,
    uint32_t width,
    uint32_t height) {
    D3D12_HEAP_PROPERTIES heap{};
    heap.Type = D3D12_HEAP_TYPE_DEFAULT;

    D3D12_RESOURCE_DESC desc{};
    desc.Dimension = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
    desc.Width = width;
    desc.Height = height;
    desc.DepthOrArraySize = 1;
    desc.MipLevels = 1;
    desc.Format = format;
    desc.SampleDesc.Count = 1;
    desc.Layout = D3D12_TEXTURE_LAYOUT_UNKNOWN;
    desc.Flags = D3D12_RESOURCE_FLAG_ALLOW_UNORDERED_ACCESS;

    ComPtr<ID3D12Resource> resource;
    if (FAILED(device->CreateCommittedResource(
            &heap,
            D3D12_HEAP_FLAG_NONE,
            &desc,
            D3D12_RESOURCE_STATE_UNORDERED_ACCESS,
            nullptr,
            IID_PPV_ARGS(&resource)))) {
        return {};
    }
    return resource;
}

bool WaitQueueIdle(ID3D12Device* device, ID3D12CommandQueue* queue) {
    ComPtr<ID3D12Fence> fence;
    if (FAILED(device->CreateFence(
            0, D3D12_FENCE_FLAG_NONE, IID_PPV_ARGS(&fence)))) {
        return false;
    }
    HANDLE eventHandle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!eventHandle) return false;

    bool ok = false;
    if (SUCCEEDED(queue->Signal(fence.Get(), 1)) &&
        SUCCEEDED(fence->SetEventOnCompletion(1, eventHandle))) {
        ok = WaitForSingleObject(eventHandle, 10000) == WAIT_OBJECT_0;
    }
    CloseHandle(eventHandle);
    return ok;
}

template <typename T>
ComPtr<T> OpenNamedSharedObject(
    ID3D12Device* device,
    const std::wstring& name) {
    HANDLE handle = nullptr;
    HRESULT hr = device->OpenSharedHandleByName(
        name.c_str(), GENERIC_ALL, &handle);
    if (FAILED(hr) || !handle) {
        Log("SHARE: OpenSharedHandleByName(%ls) failed hr=0x%08x",
            name.c_str(), static_cast<unsigned>(hr));
        return {};
    }

    ComPtr<T> object;
    hr = device->OpenSharedHandle(handle, IID_PPV_ARGS(&object));
    CloseHandle(handle);
    if (FAILED(hr)) {
        Log("SHARE: OpenSharedHandle(%ls) failed hr=0x%08x",
            name.c_str(), static_cast<unsigned>(hr));
        return {};
    }

    Log("SHARE: opened %ls", name.c_str());
    return object;
}

int RunBridge(
    const std::wstring& session,
    uint32_t width,
    uint32_t height) {
    const auto exe = ExePath();
    if (exe.empty()) {
        Log("FATAL: GetModuleFileNameW failed");
        return 2;
    }
    const auto dir = exe.parent_path();

    std::wstring lower = exe.filename().wstring();
    for (auto& c : lower) c = static_cast<wchar_t>(towlower(c));
    if (lower.find(L"nvngx.dll") == std::wstring::npos) {
        Log("FATAL: process image must contain nvngx.dll");
        return 3;
    }

    const auto snippetPath = dir / L"nvngx_dlssnr.dll";
    if (!std::filesystem::exists(snippetPath)) {
        Log("FATAL: missing %ls", snippetPath.c_str());
        return 4;
    }

    Log("BRIDGE: session=%ls size=%ux%u", session.c_str(), width, height);

    ScopedArchSpoof arch;
    if (!arch.Install()) return 5;

    auto adapter = PickNvidiaAdapter();
    if (!adapter) return 6;

    ComPtr<ID3D12Device> device;
    HRESULT hr = D3D12CreateDevice(
        adapter.Get(), D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&device));
    if (FAILED(hr)) {
        Log("D3D12: CreateDevice failed hr=0x%08x", static_cast<unsigned>(hr));
        return 7;
    }

    auto input = OpenNamedSharedObject<ID3D12Resource>(
        device.Get(), InputName(session));
    auto output = OpenNamedSharedObject<ID3D12Resource>(
        device.Get(), OutputName(session));
    auto sharedFence = OpenNamedSharedObject<ID3D12Fence>(
        device.Get(), FenceName(session));
    if (!input || !output || !sharedFence) return 8;

    D3D12_RESOURCE_DESC inDesc = input->GetDesc();
    D3D12_RESOURCE_DESC outDesc = output->GetDesc();
    Log("SHARE: input fmt=%u %llux%u output fmt=%u %llux%u",
        static_cast<unsigned>(inDesc.Format),
        static_cast<unsigned long long>(inDesc.Width), inDesc.Height,
        static_cast<unsigned>(outDesc.Format),
        static_cast<unsigned long long>(outDesc.Width), outDesc.Height);

    D3D12_COMMAND_QUEUE_DESC qd{};
    qd.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;

    ComPtr<ID3D12CommandQueue> queue;
    ComPtr<ID3D12CommandAllocator> allocator;
    ComPtr<ID3D12GraphicsCommandList> list;
    hr = device->CreateCommandQueue(&qd, IID_PPV_ARGS(&queue));
    if (SUCCEEDED(hr)) {
        hr = device->CreateCommandAllocator(
            D3D12_COMMAND_LIST_TYPE_DIRECT, IID_PPV_ARGS(&allocator));
    }
    if (SUCCEEDED(hr)) {
        hr = device->CreateCommandList(
            0, D3D12_COMMAND_LIST_TYPE_DIRECT,
            allocator.Get(), nullptr, IID_PPV_ARGS(&list));
    }
    if (FAILED(hr)) {
        Log("D3D12: command objects failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return 9;
    }

    NVSDK_NGX_Result ngx = NVSDK_NGX_D3D12_Init(
        kDlssNrApplicationId, dir.c_str(), device.Get());
    Log("NGX CORE: Init -> 0x%08x", static_cast<unsigned>(ngx));
    if (ngx != NVSDK_NGX_Result_Success) return 10;

    NVSDK_NGX_Parameter* params = nullptr;
    ngx = NVSDK_NGX_D3D12_GetCapabilityParameters(&params);
    Log("NGX CORE: GetCapabilityParameters -> 0x%08x params=%p",
        static_cast<unsigned>(ngx), static_cast<void*>(params));
    if (ngx != NVSDK_NGX_Result_Success || !params) {
        NVSDK_NGX_D3D12_Shutdown1(device.Get());
        return 11;
    }

    HMODULE snippet = LoadLibraryExW(
        snippetPath.c_str(), nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
        LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!snippet) {
        Log("SNIPPET: LoadLibrary failed win32=%lu", GetLastError());
        NVSDK_NGX_D3D12_DestroyParameters(params);
        NVSDK_NGX_D3D12_Shutdown1(device.Get());
        return 12;
    }

    auto initExt = Export<SnippetInitExtFn>(
        snippet, "NVSDK_NGX_D3D12_Init_Ext");
    auto createFeature = Export<SnippetCreateFeatureFn>(
        snippet, "NVSDK_NGX_D3D12_CreateFeature");
    auto evaluateFeature = Export<SnippetEvaluateFeatureFn>(
        snippet, "NVSDK_NGX_D3D12_EvaluateFeature");
    auto releaseFeature = Export<SnippetReleaseFeatureFn>(
        snippet, "NVSDK_NGX_D3D12_ReleaseFeature");
    auto snippetShutdown = Export<SnippetShutdownFn>(
        snippet, "NVSDK_NGX_D3D12_Shutdown1");

    if (!initExt || !createFeature || !evaluateFeature ||
        !releaseFeature || !snippetShutdown) {
        Log("SNIPPET: required exports incomplete");
        FreeLibrary(snippet);
        NVSDK_NGX_D3D12_DestroyParameters(params);
        NVSDK_NGX_D3D12_Shutdown1(device.Get());
        return 13;
    }

    ngx = initExt(
        kDlssNrApplicationId, dir.c_str(), device.Get(),
        NVSDK_NGX_Version_API, params);
    Log("SNIPPET: Init_Ext -> 0x%08x", static_cast<unsigned>(ngx));
    if (ngx != NVSDK_NGX_Result_Success) {
        FreeLibrary(snippet);
        NVSDK_NGX_D3D12_DestroyParameters(params);
        NVSDK_NGX_D3D12_Shutdown1(device.Get());
        return 14;
    }

    SetCreateParameters(params, width, height);

    NVSDK_NGX_Handle* feature = nullptr;
    ngx = createFeature(
        list.Get(), kFeatureDlssNr, params, &feature);
    Log("SNIPPET: CreateFeature(18) -> 0x%08x handle=%p",
        static_cast<unsigned>(ngx), static_cast<void*>(feature));
    if (ngx != NVSDK_NGX_Result_Success || !feature) {
        snippetShutdown(device.Get());
        FreeLibrary(snippet);
        NVSDK_NGX_D3D12_DestroyParameters(params);
        NVSDK_NGX_D3D12_Shutdown1(device.Get());
        return 15;
    }

    hr = list->Close();
    if (FAILED(hr)) {
        Log("D3D12: close create list failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return 16;
    }
    {
        ID3D12CommandList* lists[]{ list.Get() };
        queue->ExecuteCommandLists(1, lists);
    }
    if (!WaitQueueIdle(device.Get(), queue.Get())) {
        Log("D3D12: create-feature queue wait timed out");
        return 17;
    }

    auto motion = CreateAuxTexture(
        device.Get(), DXGI_FORMAT_R16G16_FLOAT, width, height);
    auto depth = CreateAuxTexture(
        device.Get(), DXGI_FORMAT_R32_FLOAT, width, height);
    if (!motion || !depth) {
        Log("D3D12: auxiliary texture creation failed");
        return 18;
    }

    // Descriptor heap used only to clear the synthetic guidance textures.
    D3D12_DESCRIPTOR_HEAP_DESC heapDesc{};
    heapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
    heapDesc.NumDescriptors = 2;
    heapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;

    ComPtr<ID3D12DescriptorHeap> heap;
    hr = device->CreateDescriptorHeap(&heapDesc, IID_PPV_ARGS(&heap));
    if (FAILED(hr)) {
        Log("D3D12: descriptor heap failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return 19;
    }

    const UINT stride = device->GetDescriptorHandleIncrementSize(
        D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);
    auto cpu0 = heap->GetCPUDescriptorHandleForHeapStart();
    auto gpu0 = heap->GetGPUDescriptorHandleForHeapStart();
    auto cpu1 = cpu0;
    cpu1.ptr += stride;
    auto gpu1 = gpu0;
    gpu1.ptr += stride;

    D3D12_UNORDERED_ACCESS_VIEW_DESC mvUav{};
    mvUav.Format = DXGI_FORMAT_R16G16_FLOAT;
    mvUav.ViewDimension = D3D12_UAV_DIMENSION_TEXTURE2D;
    device->CreateUnorderedAccessView(motion.Get(), nullptr, &mvUav, cpu0);

    D3D12_UNORDERED_ACCESS_VIEW_DESC depthUav{};
    depthUav.Format = DXGI_FORMAT_R32_FLOAT;
    depthUav.ViewDimension = D3D12_UAV_DIMENSION_TEXTURE2D;
    device->CreateUnorderedAccessView(depth.Get(), nullptr, &depthUav, cpu1);

    hr = allocator->Reset();
    if (SUCCEEDED(hr)) {
        hr = list->Reset(allocator.Get(), nullptr);
    }
    if (FAILED(hr)) {
        Log("D3D12: reset evaluate list failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return 20;
    }

    ID3D12DescriptorHeap* heaps[]{ heap.Get() };
    list->SetDescriptorHeaps(1, heaps);

    const float zero[4]{ 0, 0, 0, 0 };
    const float one[4]{ 1, 1, 1, 1 };
    list->ClearUnorderedAccessViewFloat(
        gpu0, cpu0, motion.Get(), zero, 0, nullptr);
    list->ClearUnorderedAccessViewFloat(
        gpu1, cpu1, depth.Get(), one, 0, nullptr);

    // Input is produced by D3D11 before fence value 1. Output returns to COMMON
    // before signaling value 2 so the D3D11 side can consume it.
    hr = queue->Wait(sharedFence.Get(), kInputReadyFenceValue);
    if (FAILED(hr)) {
        Log("FENCE: queue wait input failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return 21;
    }

    std::array<D3D12_RESOURCE_BARRIER, 4> barriers{};
    auto transition = [](ID3D12Resource* r,
                         D3D12_RESOURCE_STATES before,
                         D3D12_RESOURCE_STATES after) {
        D3D12_RESOURCE_BARRIER b{};
        b.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
        b.Transition.pResource = r;
        b.Transition.Subresource =
            D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
        b.Transition.StateBefore = before;
        b.Transition.StateAfter = after;
        return b;
    };

    barriers[0] = transition(
        input.Get(), D3D12_RESOURCE_STATE_COMMON,
        D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE);
    barriers[1] = transition(
        output.Get(), D3D12_RESOURCE_STATE_COMMON,
        D3D12_RESOURCE_STATE_UNORDERED_ACCESS);
    barriers[2] = transition(
        motion.Get(), D3D12_RESOURCE_STATE_UNORDERED_ACCESS,
        D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE);
    barriers[3] = transition(
        depth.Get(), D3D12_RESOURCE_STATE_UNORDERED_ACCESS,
        D3D12_RESOURCE_STATE_NON_PIXEL_SHADER_RESOURCE);
    list->ResourceBarrier(
        static_cast<UINT>(barriers.size()), barriers.data());

    SetEvaluateParameters(
        params, input.Get(), output.Get(),
        motion.Get(), depth.Get(), width, height);

    ngx = evaluateFeature(
        list.Get(), feature, params, nullptr);
    Log("SNIPPET: EvaluateFeature -> 0x%08x",
        static_cast<unsigned>(ngx));

    // Only shared resources need to return to COMMON for the client.
    std::swap(
        barriers[0].Transition.StateBefore,
        barriers[0].Transition.StateAfter);
    std::swap(
        barriers[1].Transition.StateBefore,
        barriers[1].Transition.StateAfter);
    list->ResourceBarrier(2, barriers.data());

    hr = list->Close();
    if (FAILED(hr)) {
        Log("D3D12: close evaluate list failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return 22;
    }

    {
        ID3D12CommandList* lists[]{ list.Get() };
        queue->ExecuteCommandLists(1, lists);
    }

    hr = queue->Signal(sharedFence.Get(), kOutputReadyFenceValue);
    if (FAILED(hr)) {
        Log("FENCE: signal output failed hr=0x%08x",
            static_cast<unsigned>(hr));
        return 23;
    }

    Log("BRIDGE: output signaled fence=%llu",
        static_cast<unsigned long long>(kOutputReadyFenceValue));

    // The shared fence guarantees the evaluation command list completed before
    // the client reads output. We can now tear down.
    WaitQueueIdle(device.Get(), queue.Get());

    releaseFeature(feature);
    snippetShutdown(device.Get());
    FreeLibrary(snippet);
    NVSDK_NGX_D3D12_DestroyParameters(params);
    NVSDK_NGX_D3D12_Shutdown1(device.Get());

    Log("SUCCESS: cross-process shared-texture Evaluate completed");
    return ngx == NVSDK_NGX_Result_Success ? 0 : 30;
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    const auto exe = ExePath();
    const auto logPath =
        (exe.empty() ? std::filesystem::path(L".") : exe.parent_path()) /
        L"magpie-dlssnr-worker-bridge.log";
    _wfopen_s(&g_log, logPath.c_str(), L"wb");

    Log("=== Magpie DLSSNR worker bridge probe ===");
    Log("PROCESS: %ls", exe.c_str());

    int rc = 64;
    if (argc == 5 && std::wstring_view(argv[1]) == L"--bridge-probe") {
        const std::wstring session = argv[2];
        const uint32_t width =
            static_cast<uint32_t>(_wcstoui64(argv[3], nullptr, 10));
        const uint32_t height =
            static_cast<uint32_t>(_wcstoui64(argv[4], nullptr, 10));
        rc = RunBridge(session, width, height);
    } else {
        Log("USAGE: nvngx.dll --bridge-probe <session> <width> <height>");
    }

    Log("EXIT: %d", rc);
    if (g_log) {
        fclose(g_log);
        g_log = nullptr;
    }
    return rc;
}
